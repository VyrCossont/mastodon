# frozen_string_literal: true

class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  include Localized
  include UserTrackingConcern
  include SessionTrackingConcern
  include CacheConcern
  include DomainControlHelper

  helper_method :current_account
  helper_method :current_session
  helper_method :current_theme
  helper_method :single_user_mode?
  helper_method :use_seamless_external_login?
  helper_method :omniauth_only?
  helper_method :sso_account_settings
  helper_method :whitelist_mode?

  rescue_from ActionController::ParameterMissing, Paperclip::AdapterRegistry::NoHandlerError, with: :bad_request
  rescue_from Mastodon::NotPermittedError, with: :forbidden
  rescue_from ActionController::RoutingError, ActiveRecord::RecordNotFound, with: :not_found
  rescue_from ActionController::UnknownFormat, with: :not_acceptable
  rescue_from ActionController::InvalidAuthenticityToken, with: :unprocessable_entity
  rescue_from Mastodon::RateLimitExceededError, with: :too_many_requests

  rescue_from HTTP::Error, OpenSSL::SSL::SSLError, with: :internal_server_error
  rescue_from Mastodon::RaceConditionError, Stoplight::Error::RedLight, ActiveRecord::SerializationFailure, with: :service_unavailable

  rescue_from Seahorse::Client::NetworkingError do |e|
    Rails.logger.warn "Storage server error: #{e}"
    service_unavailable
  end

  before_action :store_current_location, except: :raise_not_found, unless: :devise_controller?
  before_action :require_functional!, if: :user_signed_in?

  skip_before_action :verify_authenticity_token, only: :raise_not_found

  def raise_not_found
    raise ActionController::RoutingError, "No route matches #{params[:unmatched_route]}"
  end

  private

  def authorized_fetch_mode?
    ENV['AUTHORIZED_FETCH'] == 'true' || Rails.configuration.x.whitelist_mode
  end

  def public_fetch_mode?
    !authorized_fetch_mode?
  end

  def store_current_location
    store_location_for(:user, request.url) unless [:json, :rss].include?(request.format&.to_sym)
  end

  def require_functional!
    redirect_to edit_user_registration_path unless current_user.functional?
  end

  def after_sign_out_path_for(_resource_or_scope)
    if ENV['OMNIAUTH_ONLY'] == 'true' && ENV['OIDC_ENABLED'] == 'true'
      '/auth/auth/openid_connect/logout'
    else
      new_user_session_path
    end
  end

  protected

  def truthy_param?(key)
    ActiveModel::Type::Boolean.new.cast(params[key])
  end

  def forbidden
    respond_with_error(403)
  end

  def not_found
    respond_with_error(404)
  end

  def gone
    respond_with_error(410)
  end

  def unprocessable_entity
    respond_with_error(422)
  end

  def not_acceptable
    respond_with_error(406)
  end

  def bad_request
    respond_with_error(400)
  end

  def internal_server_error
    respond_with_error(500)
  end

  def service_unavailable
    respond_with_error(503)
  end

  def too_many_requests
    respond_with_error(429)
  end

  def single_user_mode?
    @single_user_mode ||= Rails.configuration.x.single_user_mode && Account.where('id > 0').exists?
  end

  def use_seamless_external_login?
    Devise.pam_authentication || Devise.ldap_authentication
  end

  def omniauth_only?
    ENV['OMNIAUTH_ONLY'] == 'true'
  end

  def sso_account_settings
    ENV.fetch('SSO_ACCOUNT_SETTINGS')
  end

  def current_account
    return @current_account if defined?(@current_account)

    @current_account = current_user&.account
  end

  def current_session
    return @current_session if defined?(@current_session)

    @current_session = SessionActivation.find_by(session_id: cookies.signed['_session_id']) if cookies.signed['_session_id'].present?
  end

  def current_theme
    return Setting.theme unless Themes.instance.names.include? current_user&.setting_theme

    current_user.setting_theme
  end

  def respond_with_error(code)
    respond_to do |format|
      format.any  { render "errors/#{code}", layout: 'error', status: code, formats: [:html] }
      format.json { render json: { error: Rack::Utils::HTTP_STATUS_CODES[code] }, status: code }
    end
  end

  def feditrace_log?
    Rails.configuration.x.feditrace_enabled && request.query_parameters[Feditrace::PARAM].present?
  end

  def feditrace_log
    Feditrace.log(feditrace_status_id, feditrace_requesting_domain, request)
  rescue NameError => e
    # NameError will happen if we're not in a controller that has access to the signed request.
    Rails.logger.warn "feditrace_log called from a controller with no feditrace_status_id: #{e}"
  end

  # Known legit domain from a signed request.
  def feditrace_requesting_domain
    begin
      signed_request_actor&.domain
    rescue SignatureVerificationError
      # SignatureVerificationError means the signed request was bad, but something probably checked it before we got here anyway.
    end
  rescue NameError => e
    # NameError will happen if we're not in a controller that has access to `signed_request_actor`,
    # in which case `SignatureVerificationError` doesn't exist either, hence the nesting here.
    Rails.logger.warn "feditrace_requesting_domain called from a controller with no signed_request_actor: #{e}"
  end

  # Override this for classes that have a `@status`.
  def feditrace_status_id
    nil
  end
end
