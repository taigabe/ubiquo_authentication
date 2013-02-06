module UbiquoAuthentication
  module Filters
    class RoleFilter < Ubiquo::Filters::SelectFilter

      def configure(field, roles, options = {})
        defaults = {
          :html_options => {:multiple => true, :size => 5},
          :all_caption => nil
        }
        @options = super(field, roles, defaults.merge(options))
      end

    end
  end
end
