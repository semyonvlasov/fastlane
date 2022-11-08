require_relative '../model'

module Spaceship
  class ConnectAPI
    class ReviewRejection
      include Spaceship::ConnectAPI::Model

      attr_accessor :reason

      attr_mapping({
         "reason" => "reason",
       })

      def self.type
        return "reviewRejections"
      end

      #
      # API
      #

      def guideline_section
        reason && reason['reasonSection']
      end

      def guideline_description
        reason && reason['reasonDescription']
      end

      def guideline_code
        reason && reason['reasonCode']
      end
    end
  end
end
