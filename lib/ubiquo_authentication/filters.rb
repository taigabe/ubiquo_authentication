require 'ubiquo_authentication/filters/role_filter'

module UbiquoAuthentication
  module Filters
  end
end

Ubiquo::Filters.send(:include, UbiquoAuthentication::Filters)
