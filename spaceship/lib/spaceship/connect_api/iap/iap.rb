require 'spaceship/connect_api/iap/client'

module Spaceship
  class ConnectAPI
    module IAP
      module API
        def iap_request_client=(iap_request_client)
          @iap_request_client = iap_request_client
        end

        def iap_request_client
          return @iap_request_client if @iap_request_client
          raise TypeError, "You need to instantiate this module with iap_request_client"
        end

        #
        # inAppPurchases
        #

        def get_in_app_purchases(app_id:, filter: nil, includes: nil, limit: nil, sort: nil)
          params = iap_request_client.build_params(filter: filter, includes: includes, limit: limit, sort: sort)
          iap_request_client.get("apps/#{app_id}/inAppPurchasesV2", params)
        end

        #
        # subscriptions
        #

        def get_subscription(purchase_id:, includes: nil)
          params = iap_request_client.build_params(filter: nil, includes: includes, limit: nil, sort: nil)
          iap_request_client.get("subscriptions/#{purchase_id}", params)
        end

        def get_subscriptions(family_id:, filter: nil, includes: nil, limit: nil, sort: nil)
          params = iap_request_client.build_params(filter: filter, includes: includes, limit: limit, sort: sort)
          iap_request_client.get("subscriptionGroups/#{family_id}/subscriptions", params)
        end

        def create_subscription(name:, product_id:, family_id:, available_in_all_territories: nil, family_sharable: nil, review_note: nil, subscription_period: nil, group_level: nil)
          attributes = {
            name: name,
            productId: product_id
          }

          # Optional Params
          attributes[:availableInAllTerritories] = available_in_all_territories unless available_in_all_territories.nil?
          attributes[:familySharable] = family_sharable unless family_sharable.nil?
          attributes[:reviewNote] = review_note unless review_note.nil?
          attributes[:subscriptionPeriod] = subscription_period unless subscription_period.nil?
          attributes[:groupLevel] = group_level unless group_level.nil?

          params = {
            data: {
              type: 'subscriptions', # Hard coded value
              attributes: attributes,
              relationships: {
                group: {
                  data: {
                    id: family_id,
                    type: 'subscriptionGroups' # Hard coded value
                  }
                }
              }
            }
          }

          iap_request_client.post('subscriptions', params)
        end

        #
        # subscriptionGroups
        #

        def get_subscription_group(family_id:, includes: nil)
          params = iap_request_client.build_params(filter: nil, includes: includes, limit: nil, sort: nil)
          iap_request_client.get("subscriptionGroups/#{family_id}", params)
        end

        def get_subscription_groups(app_id:, filter: nil, includes: nil, limit: nil, sort: nil)
          params = iap_request_client.build_params(filter: filter, includes: includes, limit: limit, sort: sort)
          iap_request_client.get("apps/#{app_id}/subscriptionGroups", params)
        end

        def create_subscription_group(reference_name:, app_id:)
          params = {
            data: {
              type: 'subscriptionGroups', # Hard coded value
              attributes: {
                referenceName: reference_name
              },
              relationships: {
                app: {
                  data: {
                    id: app_id,
                    type: 'apps' # Hard coded value
                  }
                }
              },
            }
          }

          iap_request_client.post('subscriptionGroups', params)
        end

        #
        # subscriptionGroupLocalizations
        #

        def get_subscription_group_localization(localization_id:, includes: nil)
          params = iap_request_client.build_params(filter: nil, includes: includes, limit: nil, sort: nil)
          iap_request_client.get("subscriptionGroupLocalizations/#{localization_id}", params)
        end

        def get_subscription_group_localizations(family_id:, includes: nil, limit: nil)
          params = iap_request_client.build_params(filter: nil, includes: includes, limit: limit, sort: nil)
          iap_request_client.get("subscriptionGroups/#{family_id}/subscriptionGroupLocalizations", params)
        end

        def create_subscription_group_localization(custom_app_name:, locale:, name:, family_id:)
          params = {
            data: {
              type: 'subscriptionGroupLocalizations',
              attributes: {
                customAppName: custom_app_name,
                locale: locale,
                name: name
              },
              relationships: {
                subscriptionGroup: {
                  data: {
                    id: family_id,
                    type: 'subscriptionGroups'
                  }
                }
              }
            }
          }

          iap_request_client.post('subscriptionGroupLocalizations', params)
        end

        def update_subscription_group_localization(custom_app_name:, name:, localization_id:)
          params = {
            data: {
              id: localization_id,
              type: 'subscriptionGroupLocalizations',
              attributes: {
                customAppName: custom_app_name,
                name: name
              }
            }
          }

          iap_request_client.patch("subscriptionGroupLocalizations/#{localization_id}", params)
        end

        #
        # subscriptionIntroductoryOffers
        #

        def get_subscription_introductory_offers(app_id:, filter: nil, includes: nil, limit: nil, sort: nil)
          params = iap_request_client.build_params(filter: filter, includes: includes, limit: limit, sort: sort)
          iap_request_client.get("subscriptions/#{app_id}/introductoryOffers", params)
        end

        #
        # subscriptionPrices
        #

        def get_subscription_prices(app_id:, filter: nil, includes: nil, limit: nil, sort: nil)
          params = iap_request_client.build_params(filter: filter, includes: includes, limit: limit, sort: sort)
          iap_request_client.get("subscriptions/#{app_id}/prices", params)
        end

        #
        # subscriptionLocalizations
        #

        def create_subscription_localization(purchase_id:, locale:, name:, description: nil)
          attributes = {
            name: name,
            locale: locale
          }

          # Optional Attributes
          attributes[:description] = description unless description.nil?

          params = {
            data: {
              type: 'subscriptionLocalizations',
              attributes: attributes,
              relationships: {
                subscription: {
                  data: {
                    id: purchase_id,
                    type: 'subscriptions'
                  }
                }
              }
            }
          }

          iap_request_client.post('subscriptionLocalizations', params)
        end

        # def patch_age_rating_declaration(age_rating_declaration_id: nil, attributes: nil)
        #   body = {
        #     data: {
        #       type: "ageRatingDeclarations",
        #       id: age_rating_declaration_id,
        #       attributes: attributes
        #     }
        #   }

        #   iap_request_client.patch("ageRatingDeclarations/#{age_rating_declaration_id}", body)
        # end

      end
    end
  end
end