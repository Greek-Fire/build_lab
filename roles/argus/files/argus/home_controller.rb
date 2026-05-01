class HomeController < ApplicationController
  def index
    render html: "<h1>Argus is running</h1>".html_safe
  end
end