require 'rails'
require 'action_controller/railtie'
require 'active_record/railtie'

module Argus
  class Application < Rails::Application
    config.load_defaults 7.0

    config.eager_load = false
    config.consider_all_requests_local = true
  end
end