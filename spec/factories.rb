require 'factory_girl'

FactoryGirl.define do
  sequence :client_name do |n|
    "Client ##{n}"
  end
  
  sequence :user_name do |n|
    "User ##{n}" 
  end
  
  factory :owner, :class => TestApp::User do
    name { generate(:user_name) }
    password_hash { OAuth2.random_string }
  end
  
  
  factory :client, :class => OAuth2::Model::Client do
    client_id { OAuth2.random_string }
    client_secret { OAuth2.random_string }
    name { generate(:client_name) }
    redirect_uri "https://client.example.com/cb"
  end
  
  factory :authorization, :class => OAuth2::Model::Authorization do
    client FactoryGirl.build(:client)
    code { OAuth2.random_string }
    expires_at nil
  end
end

