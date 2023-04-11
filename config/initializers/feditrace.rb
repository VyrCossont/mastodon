Rails.application.configure do
  config.x.feditrace_enabled = ENV['FEDITRACE_ENABLED'] == 'true'
  config.x.feditrace_scope = case ENV.fetch('FEDITRACE_SCOPE', nil)
                             when 'public_or_unlisted'
                               :public_or_unlisted
                             when 'public'
                               :public
                             else
                               :discoverable
                             end
  config.x.feditrace_log_path = ENV.fetch('FEDITRACE_LOG_PATH', nil)
  config.x.feditrace_secret = ENV.fetch('FEDITRACE_SECRET', nil)
end
