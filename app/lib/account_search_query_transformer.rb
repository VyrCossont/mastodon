# frozen_string_literal: true

class AccountSearchQueryTransformer < Parslet::Transform
  class Query
    attr_reader :should_clauses, :must_not_clauses, :must_clauses, :filter_clauses

    def initialize(clauses)
      grouped = clauses.group_by(&:operator).to_h
      @should_clauses = grouped.fetch(:should, [])
      @must_not_clauses = grouped.fetch(:must_not, [])
      @must_clauses = grouped.fetch(:must, [])
      @filter_clauses = grouped.fetch(:filter, [])
    end

    def query(likely_acct, search_scope, account_exists, following, following_ids)
      full_text_enabled = account_exists && search_scope != :classic

      search_fields = %w(acct.edge_ngram acct)
      search_fields += %w(display_name.edge_ngram display_name) unless likely_acct
      search_fields += %w(text.stemmed text) if full_text_enabled

      params = {
        must: must_clauses.map { |clause| clause_to_query(clause, search_fields) },
        must_not: must_not_clauses.map { |clause| clause_to_query(clause, search_fields) },
        should: should_clauses.map { |clause| clause_to_query(clause, search_fields) },
        filter: filter_clauses.map { |clause| clause_to_query(clause, search_fields) },
      }

      if account_exists
        if following
          params[:must] << { terms: { id: following_ids } }
        elsif following_ids.any?
          params[:should] << { terms: { id: following_ids, boost: 0.5 } }
        end
      end

      if full_text_enabled && search_scope == :discoverable
        params[:filter] << { term: { discoverable: true } }
        params[:filter] << { term: { silenced: false } }
      end

      { bool: params }
    end

    private

    def clause_to_query(clause, search_fields)
      case clause
      when TermClause
        { multi_match: { type: 'most_fields', query: clause.term, fields: search_fields, operator: 'and' } }
      when PhraseClause
        { match_phrase: { text: { query: clause.phrase } } }
      when PrefixClause
        { clause.query => { clause.filter => clause.term } }
      when TagClause
        { term: { tags: clause.tag } }
      else
        raise Mastodon::SyntaxError.new("Unexpected clause type: #{clause}")
      end
    end
  end

  class Operator
    class << self
      def symbol(str)
        case str
        when '+'
          :must
        when '-'
          :must_not
        when nil
          :should
        else
          raise Mastodon::SyntaxError.new("Unknown operator: #{str}")
        end
      end
    end
  end

  class TermClause
    attr_reader :prefix, :operator, :term

    def initialize(prefix, operator, term)
      @prefix = prefix
      @operator = Operator.symbol(operator)
      @term = term
    end
  end

  class PhraseClause
    attr_reader :prefix, :operator, :phrase

    def initialize(prefix, operator, phrase)
      @prefix = prefix
      @operator = Operator.symbol(operator)
      @phrase = phrase
    end
  end

  class PrefixClause
    attr_reader :filter, :operator, :term, :query

    def initialize(prefix, operator, term)
      @query = :term

      case operator
      when '+', nil
        @operator = :filter
      when '-'
        @operator = :must_not
      else
        raise Mastodon::SyntaxError.new("Unknown operator: #{str}")
      end

      case prefix
      when 'domain', 'is'
        @filter = prefix.to_s
        @term = term
      else
        raise Mastodon::SyntaxError
      end
    end
  end

  class TagClause
    attr_reader :prefix, :operator, :tag

    def initialize(prefix, operator, tag)
      @prefix = prefix
      @tag = tag

      case operator
      when '+', nil
        @operator = :filter
      when '-'
        @operator = :must_not
      else
        raise Mastodon::SyntaxError.new("Unknown operator: #{str}")
      end
    end
  end

  rule(clause: subtree(:clause)) do
    prefix   = clause[:prefix][:term].to_s if clause[:prefix]
    operator = clause[:operator]&.to_s

    if clause[:prefix]
      PrefixClause.new(prefix, operator, clause[:term].to_s)
    elsif clause[:term]
      TermClause.new(prefix, operator, clause[:term].to_s)
    elsif clause[:shortcode]
      TermClause.new(prefix, operator, ":#{clause[:shortcode][:term]}:")
    elsif clause[:hashtag]
      TagClause.new(prefix, operator, clause[:hashtag][:term].to_s)
    elsif clause[:phrase]
      PhraseClause.new(prefix, operator, clause[:phrase].is_a?(Array) ? clause[:phrase].map { |p| p[:term].to_s }.join(' ') : clause[:phrase].to_s)
    else
      raise Mastodon::SyntaxError.new("Unexpected clause type: #{clause}")
    end
  end

  rule(query: sequence(:clauses)) { Query.new(clauses) }
end
