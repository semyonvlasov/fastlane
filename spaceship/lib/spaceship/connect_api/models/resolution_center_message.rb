require_relative '../model'
require_relative './review_rejection'

module Spaceship
  class ConnectAPI
    class ResolutionCenterMessage
      include Spaceship::ConnectAPI::Model

      attr_accessor :message
      attr_accessor :created_date

      attr_mapping({
         "messageBody" =>  "message",
         "createdDate" => "created_date",
       })

      def self.type
        return "resolutionCenterMessages"
      end

      #
      # API
      #

      def self.all(client: nil, resolution_center_thread_id:)
        client ||= Spaceship::ConnectAPI
        resps = client.get_resolution_center_messages(resolution_center_thread_id: resolution_center_thread_id).all_pages
        return resps.flat_map(&:to_models)
      end
    end
  end
end
