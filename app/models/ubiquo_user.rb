class UbiquoUser < ActiveRecord::Base
  include UbiquoAuthentication::Concerns::Models::UbiquoUser
end
