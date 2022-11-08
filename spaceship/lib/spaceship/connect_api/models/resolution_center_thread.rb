require_relative '../model'
require_relative './resolution_center_message'

module Spaceship
  class ConnectAPI
    class ResolutionCenterThread
      include Spaceship::ConnectAPI::Model

      attr_accessor :state

      attr_accessor :can_developer_add_note
      attr_accessor :objectionable_content
      attr_accessor :thread_type
      attr_accessor :created_date
      attr_accessor :last_message_response_date

      attr_mapping({
         "state" =>  "state",

         "canDeveloperAddNote" => "can_developer_add_note",
         "objectionableContent" => "objectionable_content",
         "threadType" => "thread_type",
         "createdDate" => "created_date",
         "lastMessageResponseDate" => "last_message_response_date",
       })

      def self.type
        return "resolutionCenterThreads"
      end

      #
      # API
      #

      def self.all(client: nil, review_submission_id:)
        client ||= Spaceship::ConnectAPI
        resps = client.get_resolution_center_threads(review_submission_id: review_submission_id).all_pages
        return resps.to_models
      end


      def fetch_messages(client: nil)
        client ||= Spaceship::ConnectAPI
        resps = client.get_resolution_center_messages(resolution_center_thread_id: id)
        return resps.to_models
      end
    end
  end
end
