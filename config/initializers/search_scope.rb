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

  config.x.account_search_scope = case
  when ENV['ACCOUNT_SEARCH_SCOPE'] == 'all'
    :all
  when ENV['ACCOUNT_SEARCH_SCOPE'] == 'discoverable'
    :discoverable
  else
    :classic
  end
end
