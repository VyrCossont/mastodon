# frozen_string_literal: true

Rails.application.configure do
  config.x.search_scope = case
  when ENV['SEARCH_SCOPE'] == 'public'
    :public
  when ENV['SEARCH_SCOPE'] == 'public_or_unlisted'
    :public_or_unlisted
  else
    :classic
  end

  config.x.pg_full_text_search_enabled = ENV['PG_FULL_TEXT_SEARCH_ENABLED'] == 'true'
end
