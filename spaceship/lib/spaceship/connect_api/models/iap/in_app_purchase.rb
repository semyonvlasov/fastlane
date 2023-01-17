require_relative '../../model'
module Spaceship
  class ConnectAPI
    class InAppPurchase
      include Spaceship::ConnectAPI::Model

      # Attributes
      attr_accessor :available_in_all_territories,
                    :content_hosting,
                    :family_sharable,
                    :in_app_purchase_type,
                    :name,
                    :product_id,
                    :review_note,
                    :state

      # Relations
      attr_accessor :prices,
                    :localizations

      module Type
        CONSUMABLE = "CONSUMABLE"
        NON_CONSUMABLE = "NON_CONSUMABLE"
        NON_RENEWING_SUBSCRIPTION = "NON_RENEWING_SUBSCRIPTION"
      end

      module State
        APPROVED = "APPROVED"
        DEVELOPER_ACTION_NEEDED = "DEVELOPER_ACTION_NEEDED"
        DEVELOPER_REMOVED_FROM_SALE = "DEVELOPER_REMOVED_FROM_SALE"
        IN_REVIEW = "IN_REVIEW"
        MISSING_METADATA = "MISSING_METADATA"
        PENDING_BINARY_APPROVAL = "PENDING_BINARY_APPROVAL"
        PROCESSING_CONTENT = "PROCESSING_CONTENT"
        READY_TO_SUBMIT = "READY_TO_SUBMIT"
        REJECTED = "REJECTED"
        REMOVED_FROM_SALE = "REMOVED_FROM_SALE"
        WAITING_FOR_REVIEW = "WAITING_FOR_REVIEW"
        WAITING_FOR_UPLOAD = "WAITING_FOR_UPLOAD"
      end

      attr_mapping({
        availableInAllTerritories: 'available_in_all_territories',
        contentHosting: 'content_hosting',
        familySharable: 'family_sharable',
        inAppPurchaseType: 'in_app_purchase_type',
        name: 'name',
        productId: 'product_id',
        reviewNote: 'review_note',
        state: 'state',
        inAppPurchaseLocalizations: 'localizations',
      })

      def self.type
        return 'inAppPurchases'
      end

      #
      # In App Purchase Localizations
      #

      def get_localizations(client: nil, limit: nil, includes: nil)
        client ||= Spaceship::ConnectAPI
        resps = client.get_in_app_purchase_localizations(purchase_id: id, includes: includes, limit: limit).all_pages
        models = resps.flat_map(&:to_models)
        (self.localizations ||= []).concat(models).uniq! { |sub_loc| sub_loc.id }
        models
      end

      def get_localization(client: nil, localization_id:, includes: nil)
        client ||= Spaceship::ConnectAPI
        resps = client.get_in_app_purchase_localization(localization_id: localization_id, includes: includes)
        model = resps.to_models.first
        ((self.localizations ||= []) << model).uniq! { |sub_loc| sub_loc.id }
        model
      end

      def create_localization(client: nil, locale:, name:, description: nil)
        client ||= Spaceship::ConnectAPI
        resps = client.create_in_app_purchase_localization(purchase_id: id, locale: locale, name: name, description: description)
        model = resps.to_models.first
        ((self.localizations ||= []) << model).uniq! { |sub_loc| sub_loc.id }
        model
      end

      #
      # In-App Purchase Price Points
      #

      def get_price_points(client: nil, filter: {}, includes: Spaceship::ConnectAPI::InAppPurchasePricePoint::ESSENTIAL_INCLUDES, limit: nil)
        client ||= Spaceship::ConnectAPI
        resps = client.get_in_app_purchase_price_points(purchase_id: id, filter: filter, includes: includes, limit: limit).all_pages
        resps.flat_map(&:to_models)
      end

      #
      # In-App Purchase Price Schedules
      #

      def create_price_schedule(client: nil, in_app_purchase_price_point_id:, start_date: nil)
        client ||= Spaceship::ConnectAPI
        resps = client.create_in_app_purchase_price_schedule(purchase_id: id, in_app_purchase_price_point_id: in_app_purchase_price_point_id, start_date: start_date)
        resps.to_models.first
      end

      def get_price_schedules(client: nil, includes: Spaceship::ConnectAPI::InAppPurchasePriceSchedule::ESSENTIAL_INCLUDES, limit: nil, fields: nil)
        client ||= Spaceship::ConnectAPI
        resps = client.get_in_app_purchase_price_schedules(purchase_id: id, includes: includes, limit: limit, fields: fields).all_pages
        resps.flat_map(&:to_models)
      end

      #
      # In-App Purchase Prices
      #

      def get_prices(client: nil, filter: nil, includes: Spaceship::ConnectAPI::InAppPurchasePrice::ESSENTIAL_INCLUDES, limit: nil, fields: nil)
        client ||= Spaceship::ConnectAPI
        resps = client.get_in_app_purchase_prices(purchase_id: id, filter: filter, includes: includes, limit: limit, fields: fields).all_pages
        ((self.prices ||= []) << model).uniq! { |price| price.id }
        resps.flat_map(&:to_models)
      end

    end
  end
end
