# frozen_string_literal: true

class Feditrace
  PARAM = 'feditrace'

  ALGORITHM = 'HS256'

  # @param [Integer|String] status_id ID of Feditraced status.
  # @param [String|Symbol] requesting_domain Known domain from signed request or inbox URL being delivered to, or :placeholder when serializing for delivery to multiple domains.
  #
  # HACK: when distributing Feditraced activities, rather than re-serialize the payload for each recipient, serialize
  # the URL with the status ID as a placeholder, and later modify the URL in the JSON for each recipient.
  # SEE: ActivityPub::DeliveryWorker#feditrace_fill_placeholder
  # SEE: ActivityPub::DistributionWorker#payload
  def self.decorate_url(url, status_id, requesting_domain)
    raise Mastodon::Error, 'Feditrace.decorate_url called without a URL' if url.blank?
    raise Mastodon::Error, 'Feditrace.decorate_url called without a status ID' if status_id.blank?
    raise Mastodon::Error, 'Feditrace.decorate_url called without a requesting domain' if requesting_domain.blank?

    if requesting_domain == :placeholder
      param_value = status_id.to_s
    else
      payload = {
        iss: iss,
        sub: status_id.to_s,
        referrer: requesting_domain,
      }
      param_value = JWT.encode payload, secret, ALGORITHM
    end

    begin
      parsed_url = Addressable::URI.parse(url)
    rescue Addressable::URI::InvalidURIError => e
      Rails.logger.error "Can't rewrite status URL #{url} for Feditrace: #{e}"
      raise
    end
    raise Mastodon::InvalidParameterError, "Parsed URL is nil. This probably can't happen." if parsed_url.nil?

    query_values = parsed_url.query_values || {}
    query_values[PARAM] = param_value
    parsed_url.query_values = query_values
    parsed_url.normalize!
    parsed_url.to_s
  end

  # @param [Integer|String] status_id ID of Feditraced status.
  # @param [String|Nil] requesting_domain Known domain from signed request.
  # @param [ActionDispatch::Request|Nil] request Rails request.
  # @param [Symbol] log_type Log type: either :request for incoming requests or :delivery for outbound delivery.
  def self.log(status_id, requesting_domain, request, log_type)
    # This is normal if the request wasn't signed.
    # A very common case would be the HTML view of a status.
    return if requesting_domain.blank?

    raise Mastodon::InvalidParameterError, 'Feditrace.log called without a status ID' if status_id.blank?

    case log_type
    when :delivery
      url = nil
      ip = nil
      referrer = Rails.configuration.x.local_domain

    when :request
      raise Mastodon::InvalidParameterError, 'Feditrace.log called without a request' if request.blank?

      param_value = request.query_parameters[Feditrace::PARAM]
      raise Mastodon::InvalidParameterError, 'Feditrace.log called without a Feditrace query param value' if param_value.blank?

      begin
        payload, _header = JWT.decode param_value, secret, true, {
          algorithm: ALGORITHM,
          verify_iss: true,
          verify_sub: true,
          iss: Rails.configuration.x.local_domain,
          sub: status_id.to_s,
        }
      rescue JWT::DecodeError => e
        # This will probably happen a lot. Don't make a fuss.
        Rails.logger.warn "Invalid Feditrace query parameter #{param_value}: #{e}"
        return
      end

      url = request.original_url
      ip = request.remote_ip
      referrer = payload['referrer']

    else
      raise Mastodon::InvalidParameterError, "Feditrace.log called with an unknown log_type: #{log_type}"
    end

    log_entry = {
      time: Time.now.utc.iso8601,
      type: log_type.to_s,
      url: url,
      ip: ip,
      status_id: status_id.to_s,
      referrer: referrer,
      requesting_domain: requesting_domain,
    }

    log_path = Rails.configuration.x.feditrace_log_path
    return if log_path.blank?

    begin
      FileUtils.mkdir_p(File.expand_path('..', log_path))
      File.write(log_path, "#{JSON.generate(log_entry)}\n", mode: 'a')
    rescue IOError => e
      # If we can't write a log entry, we can still handle the rest of the request.
      Rails.logger.error "Error writing to Feditrace log #{log_path}: #{e}"
    end
  end

  class << self
    protected

    def secret
      secret = Rails.configuration.x.feditrace_secret
      raise Mastodon::InvalidParameterError, "Feditrace signing secret hasn't been set!" if secret.blank?

      secret
    end

    def iss
      Rails.configuration.x.local_domain
    end
  end
end
