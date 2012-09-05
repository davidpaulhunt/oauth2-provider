module OAuth2
  module Model
    
    module ResourceOwner
      
      module ClassMethods
        def oauth2_password_field(sym)
          class_variable_set(:@@oauth2_password_field, sym.to_s)
        end
      end
      
      def self.included(klass)
        klass.extend(ClassMethods)
        klass.has_many :oauth2_authorizations,
                       :class_name => 'OAuth2::Model::Authorization',
                       :as => :oauth2_resource_owner,
                       :dependent => :destroy
      end
      
      def get_password_field
        return nil unless self.class.class_variable_defined?(:@@oauth2_password_field)
        return __send__(self.class.class_variable_get(:@@oauth2_password_field))
      end
      
      def grant_access!(client, options = {})
        authorization = oauth2_authorizations.find_by_client_id(client.id) ||
                        Model::Authorization.create(:owner => self, :client => client)
        
        if scopes = options[:scopes]
          scopes = authorization.scopes + scopes
          authorization.update_attribute(:scope, scopes.join(' '))
        end
        
        authorization
      end
    end
    
  end
end
