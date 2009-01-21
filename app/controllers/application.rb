# Filters added to this controller apply to all controllers in the application.
# Likewise, all the methods added will be available for all controllers.

class ApplicationController < ActionController::Base
  include AuthenticatedSystem

  helper :all # include all helpers, all the time

  # enable SSO with rubycas
  before_filter CASClient::Frameworks::Rails::Filter
  before_filter :load_or_create_remote_user

  before_filter :login_from_cookie, :login_required

  # See ActionController::RequestForgeryProtection for details
  # Uncomment the :secret if you're not using the cookie session store
  protect_from_forgery # :secret => '40e4761f6fce9b879d9bd65cc8803682'
  
  # See ActionController::Base for details 
  # Uncomment this to filter the contents of submitted sensitive data parameters
  # from your application log (in this case, all fields with names like "password"). 
  # filter_parameter_logging :password
protected

  # Set the current user:
  # Will create a local user instance if not found in the local User table
  # :cas_extra_attributes: !map:HashWithIndifferentAccess 
  #   roles: crew_member
  #   rating: gm
  #   level: c
  #   id: 2
  #   lname: Fine
  #   fname: Larry
  def load_or_create_remote_user
    username = session[:cas_user]
    return false if username.blank?
    
#    user = User.find_by_login(username)
    user = User.find_or_create_by_login(:login => username, :password => "password", :password_confirmation => "password", :email => "foo@bar.com"  )

    if user
      logger.debug "Did find the user => #{username} in the local DB"
      @current_user = user
      logger.debug "Found the current user in the local DB => #{@current_user.inspect}"
      #session[:user] = user

#      user.unid = user
      # TODO: handle multiple roles
#      user.has_role(session[:cas_extra_attributes]['roles'])
#      user.profile = Profile.new(:given_name => session[:cas_extra_attributes]['fname'], :family_name => session[:cas_extra_attributes]['lname'], :rating => session[:cas_extra_attributes]['rating'],:level => session[:cas_extra_attributes]['level'], :email => session[:cas_extra_attributes]['email'] ) 

    else
      logger.debug "Did NOT find the user => #{username} in the local DB"
      return false
    end
    logger.debug("Current User = #{@current_user.inspect}")
    logger.debug("session[:user_id] = #{session[:user_id].inspect}")
    return true
  end 
end
