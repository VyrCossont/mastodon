# frozen_string_literal: true

class SearchService < BaseService
  def call(query, account, limit, options = {})
    @query   = query&.strip
    @account = account
    @options = options
    @limit   = limit.to_i
    @offset  = options[:type].blank? ? 0 : options[:offset].to_i
    @resolve = options[:resolve] || false

    default_results.tap do |results|
      next if @query.blank? || @limit.zero?

      if url_query?
        results.merge!(url_resource_results) unless url_resource.nil? || @offset.positive? || (@options[:type].present? && url_resource_symbol != @options[:type].to_sym)
      elsif @query.present?
        results[:accounts] = perform_accounts_search! if account_searchable?
        results[:statuses] = perform_statuses_search! if full_text_searchable?
        results[:hashtags] = perform_hashtags_search! if hashtag_searchable?
      end
    end
  end

  private

  def perform_accounts_search!
    AccountSearchService.new.call(
      @query,
      @account,
      limit: @limit,
      resolve: @resolve,
      offset: @offset
    )
  end

  ##
  # Note: PG full-text search has some limitations in the current iteration:
  #   - Search with any scope does not include the text of media attachments or polls.
  #   - Search with :classic scope only searches the current user's own statuses, but not favs, boosts, bookmarks, etc.
  def perform_pg_statuses_search!
    definition = Status
                 .where(deleted_at: nil)
                 .where(reblog_of_id: nil)

    definition = case Rails.configuration.x.search_scope
                 when :public
                   definition.where(visibility: :public)
                 when :public_or_unlisted
                   definition.where(visibility: [:public, :unlisted])
                 else
                   definition.where(account_id: @account.id)
                 end

    definition = definition
                 .where(
                   "websearch_to_tsquery('english', :query_text) @@ " \
                     "(to_tsvector('english', spoiler_text) || to_tsvector('english', text))",
                   { query_text: @query }
                 )

    if @options[:account_id].present?
      definition = definition.where({ account_id: @options[:account_id] })
    end

    if @options[:min_id].present?
      definition = definition.where('id > :id', { id: @options[:min_id].to_i })
    end

    if @options[:max_id].present?
      definition = definition.where('id < :id', { id: @options[:max_id].to_i })
    end

    definition.limit(@limit).offset(@offset).compact
  end

  def perform_es_statuses_search!
    statuses_index = StatusesIndex.filter(term: { searchable_by: @account.id })
    case Rails.configuration.x.search_scope
    when :public
      statuses_index = statuses_index.filter.or(term: { visibility: 'public' })
    when :public_or_unlisted
      statuses_index = statuses_index.filter.or(terms: { visibility: ['public', 'unlisted'] })
    end
    definition = parsed_query.apply(statuses_index, @account)

    if @options[:account_id].present?
      definition = definition.filter(term: { account_id: @options[:account_id] })
    end

    if @options[:min_id].present? || @options[:max_id].present?
      range      = {}
      range[:gt] = @options[:min_id].to_i if @options[:min_id].present?
      range[:lt] = @options[:max_id].to_i if @options[:max_id].present?
      definition = definition.filter(range: { id: range })
    end

    definition.limit(@limit).offset(@offset).objects.compact

  rescue Faraday::ConnectionFailed, Parslet::ParseFailed
    []
  end

  def perform_statuses_search!
    results =
      if Rails.configuration.x.pg_full_text_search_enabled
        perform_pg_statuses_search!
      elsif Chewy.enabled?
        perform_es_statuses_search!
      else
        return []
      end

    account_ids         = results.map(&:account_id)
    account_domains     = results.map(&:account_domain)
    preloaded_relations = relations_map_for_account(@account, account_ids, account_domains)

    results.reject { |status| StatusFilter.new(status, @account, preloaded_relations).filtered? }
  end

  def perform_hashtags_search!
    TagSearchService.new.call(
      @query,
      limit: @limit,
      offset: @offset,
      exclude_unreviewed: @options[:exclude_unreviewed]
    )
  end

  def default_results
    { accounts: [], hashtags: [], statuses: [] }
  end

  def url_query?
    @resolve && /\Ahttps?:\/\//.match?(@query)
  end

  def url_resource_results
    { url_resource_symbol => [url_resource] }
  end

  def url_resource
    @_url_resource ||= ResolveURLService.new.call(@query, on_behalf_of: @account)
  end

  def url_resource_symbol
    url_resource.class.name.downcase.pluralize.to_sym
  end

  def full_text_searchable?
    statuses_search? && !@account.nil? && !((@query.start_with?('#') || @query.include?('@')) && !@query.include?(' '))
  end

  def account_searchable?
    account_search? && !(@query.start_with?('#') || (@query.include?('@') && @query.include?(' ')))
  end

  def hashtag_searchable?
    hashtag_search? && !@query.include?('@')
  end

  def account_search?
    @options[:type].blank? || @options[:type] == 'accounts'
  end

  def hashtag_search?
    @options[:type].blank? || @options[:type] == 'hashtags'
  end

  def statuses_search?
    @options[:type].blank? || @options[:type] == 'statuses'
  end

  def relations_map_for_account(account, account_ids, domains)
    {
      blocking: Account.blocking_map(account_ids, account.id),
      blocked_by: Account.blocked_by_map(account_ids, account.id),
      muting: Account.muting_map(account_ids, account.id),
      following: Account.following_map(account_ids, account.id),
      domain_blocking_by_domain: Account.domain_blocking_map_by_domain(domains, account.id),
    }
  end

  def parsed_query
    SearchQueryTransformer.new.apply(SearchQueryParser.new.parse(@query))
  end
end
