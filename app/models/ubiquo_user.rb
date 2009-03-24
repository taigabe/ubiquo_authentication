require 'digest/sha1'
class UbiquoUser < ActiveRecord::Base

  has_many :ubiquo_user_roles
  has_many :roles, :through => :ubiquo_user_roles

  # Virtual attribute for the unencrypted password
  attr_accessor :password

  validates_presence_of     :login
  validates_presence_of     :password,                   :if => :password_required?
  validates_presence_of     :password_confirmation,      :if => :password_required?
  validates_length_of       :password, :within => 4..40, :if => :password_required?
  validates_confirmation_of :password,                   :if => :password_required?
  validates_presence_of     :email
  validates_uniqueness_of   :email
  validates_format_of       :email, :with => /\A([a-z0-9#_.-]+)@([a-z0-9-]+)\.([a-z.]+)\Z/i
  validates_length_of       :login, :within => 3..40
  validates_uniqueness_of   :login, :case_sensitive => false

  before_save :encrypt_password

  # prevents a ubiquo_user from submitting a crafted form that bypasses activation
  # anything else you want your ubiquo_user to change should be added here.
  attr_accessible :login, :email, :password, :password_confirmation, :is_admin, :is_active, :role_ids

  # Magic finder. It's like find_by_if_or_login
  def self.gfind(something, options={})
    case something
    when Fixnum
      find_by_id(something, options)
    when String, Symbol
      find_by_login(something.to_s, options)
    when UbiquoUser
      something
    else
      nil
    end
  end

  # Filter UbiquoUsers
  # 
  # Available filters: filter_admin: true|false|nil
  def self.filtered_search(filters = {}, options = {})
    filter_admin = filters[:filter_admin].nil? ? {} :
      {:find => {:conditions => {:is_admin => filters[:filter_admin]}}}
    with_scope(filter_admin) do
      with_scope(:find => options) do      
        UbiquoUser.find(:all)
      end
    end    
  end

  # Authenticates a ubiquo_user by their login name and unencrypted password.  Returns the ubiquo_user or nil.
  def self.authenticate(login, password)
    u = find_by_login(login) # need to get the salt
    (u && (u.authenticated?(password) ? u : nil) && (u.is_active? ? u : nil))
  end

  # Encrypts some data with the salt.
  def self.encrypt(password, salt)
    Digest::SHA1.hexdigest("--#{salt}--#{password}--")
  end

  # Encrypts the password with the ubiquo_user salt
  def encrypt(password)
    self.class.encrypt(password, salt)
  end

  def authenticated?(password)
    crypted_password == encrypt(password)
  end

  def remember_token?
    remember_token_expires_at && Time.now.utc < remember_token_expires_at
  end

  # These create and unset the fields required for remembering ubiquo_users between browser closes
  def remember_me
    remember_me_for Ubiquo::Config.context(:ubiquo_authentication).get(:remember_time)
  end

  def remember_me_for(time)
    remember_me_until time.from_now.utc
  end

  # The current ubiquo_user will not expire until 'time' is reached
  def remember_me_until(time)
    self.remember_token_expires_at = time
    self.remember_token            = encrypt("--#{remember_token_expires_at}--")
    save(false)
  end

  # Expire current_ubiquo_user inmediately
  def forget_me
    self.remember_token_expires_at = nil
    self.remember_token            = nil
    save(false)
  end
  
  def reset_password!
    returning (password = ActiveSupport::SecureRandom.base64(6)) do
      self.password = password
      self.password_confirmation = password
      self.save
    end
  end

  # Permission methods

  # adds a role to this ubiquo_user
  def add_role(role)
    role=Role.gfind(role)
    return false if role.nil?
    UbiquoUserRole.create_for_ubiquo_user_and_role(self, role)
    self.reload
    true
  end

  # removes a role from this ubiquo_user
  def remove_role(role)
    role=Role.gfind(role)
    return false if role.nil? || !roles.include?(role)
    UbiquoUserRole.destroy_for_ubiquo_user_and_role(self, role)
    self.reload
    true
  end

  # true if this ubiquo_user has specified permission
  def has_permission?(permission)
    return true if self.is_admin?
    permission = Permission.gfind(permission)
    self.roles.each do |role|
      return true if role.has_permission?(permission)
    end
    false
  end


  protected
  # before filter
  def encrypt_password
    return if password.blank?
    self.salt = Digest::SHA1.hexdigest("--#{Time.now.to_s}--#{login}--") if new_record?
    self.crypted_password = encrypt(password)
  end

  def password_required?
    crypted_password.blank? || !password.blank?
  end

end