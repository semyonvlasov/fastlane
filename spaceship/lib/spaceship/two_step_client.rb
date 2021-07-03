require 'tempfile'
require 'net/imap'

require_relative 'globals'
require_relative 'tunes/tunes_client'
require_relative 'tunes/recovery_device'

module Spaceship
  class Client
    def handle_two_step(response)
      @x_apple_id_session_id = response["x-apple-id-session-id"]
      @scnt = response["scnt"]

      r = request(:get) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth")
        update_request_headers(req)
      end

      if r.body.kind_of?(Hash) && r.body["trustedDevices"].kind_of?(Array)
        if r.body.fetch("securityCode", {})["tooManyCodesLock"].to_s.length > 0
          raise Tunes::Error.new, "Too many verification codes have been sent. Enter the last code you received, use one of your devices, or try again later."
        end

        old_client = (begin
                        Tunes::RecoveryDevice.client
                      rescue
                        nil # since client might be nil, which raises an exception
                      end)
        Tunes::RecoveryDevice.client = self # temporary set it as it's required by the factory method
        devices = r.body["trustedDevices"].collect do |current|
          Tunes::RecoveryDevice.factory(current)
        end
        Tunes::RecoveryDevice.client = old_client

        puts("Two Step Verification for account '#{self.user}' is enabled")
        puts("Please select a device to verify your identity")
        available = devices.collect do |c|
          "#{c.name}\t#{c.model_name || 'SMS'}\t(#{c.device_id})"
        end
        result = choose(*available)
        device_id = result.match(/.*\t.*\t\((.*)\)/)[1]
        select_device(r, device_id)
      elsif r.body.kind_of?(Hash) && r.body["trustedPhoneNumbers"].kind_of?(Array) && r.body["trustedPhoneNumbers"].first.kind_of?(Hash)
        raise Tunes::Error.new, 'This request requires two-factor authentication, but non-interactive mode is enabled' if @login_options[:non_interactive_mode]
        handle_two_factor(r)
      else
        raise "Invalid 2 step response #{r.body}"
      end
    end

    def handle_two_factor(response)
      two_factor_url = "https://github.com/fastlane/fastlane/tree/master/spaceship#2-step-verification"
      puts("Two Factor Authentication for account '#{self.user}' is enabled")

      security_code = response.body["securityCode"]
      # {"length"=>6,
      #  "tooManyCodesSent"=>false,
      #  "tooManyCodesValidated"=>false,
      #  "securityCodeLocked"=>false}
      code_length = security_code["length"]

      # Ask which phone number needs to be used for two factor auth
      if response.body["noTrustedDevices"]
        code_type = 'phone'
        if %i[google_account google_number google_password].all? {|s| @login_options.key? s}
          body = request_two_factor_code_with_google_voice(response.body["trustedPhoneNumbers"])
        else
          body = request_two_factor_code_from_phone_choose(response.body["trustedPhoneNumbers"], code_length)
        end
      else
        code_type = 'trusteddevice'
        # Prompt for code
        if !File.exist?(persistent_cookie_path) && self.class.spaceship_session_env.to_s.length.zero?
          puts("If you're running this in a non-interactive session (e.g. server or CI)")
          puts("check out #{two_factor_url}")
        else
          # If the cookie is set but still required, the cookie is expired
          puts("Your session cookie has been expired.")
        end
        code = ask("Please enter the #{code_length} digit code: ")
        body = { "securityCode" => { "code" => code.to_s } }.to_json
      end

      puts("Requesting session...")

      # Send securityCode back to server to get a valid session
      r = request(:post) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/verify/#{code_type}/securitycode")
        req.headers['Content-Type'] = 'application/json'
        req.body = body

        update_request_headers(req)
      end

      # we use `Spaceship::TunesClient.new.handle_itc_response`
      # since this might be from the Dev Portal, but for 2 step
      Spaceship::TunesClient.new.handle_itc_response(r.body)

      store_session

      return true
    end

    # Only needed for 2 step
    def load_session_from_file
      if File.exist?(persistent_cookie_path)
        puts("Loading session from '#{persistent_cookie_path}'") if Spaceship::Globals.verbose?
        @cookie.load(persistent_cookie_path)
        return true
      end
      return false
    end

    def load_session_from_env
      return if self.class.spaceship_session_env.to_s.length == 0
      puts("Loading session from environment variable") if Spaceship::Globals.verbose?

      file = Tempfile.new('cookie.yml')
      file.write(self.class.spaceship_session_env.gsub("\\n", "\n"))
      file.close

      begin
        @cookie.load(file.path)
      rescue => ex
        puts("Error loading session from environment")
        puts("Make sure to pass the session in a valid format")
        raise ex
      ensure
        file.unlink
      end
    end

    # Fetch the session cookie from the environment
    # (if exists)
    def self.spaceship_session_env
      ENV["FASTLANE_SESSION"] || ENV["SPACESHIP_SESSION"]
    end

    def select_device(r, device_id)
      # Request Token
      r = request(:put) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/verify/device/#{device_id}/securitycode")
        update_request_headers(req)
      end

      # we use `Spaceship::TunesClient.new.handle_itc_response`
      # since this might be from the Dev Portal, but for 2 step
      Spaceship::TunesClient.new.handle_itc_response(r.body)

      puts("Successfully requested notification")
      code = ask("Please enter the 4 digit code: ")
      puts("Requesting session...")

      # Send token back to server to get a valid session
      r = request(:post) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/verify/device/#{device_id}/securitycode")
        req.body = { "code" => code.to_s }.to_json
        req.headers['Content-Type'] = 'application/json'

        update_request_headers(req)
      end

      begin
        Spaceship::TunesClient.new.handle_itc_response(r.body) # this will fail if the code is invalid
      rescue => ex
        # If the code was entered wrong
        # {
        #   "securityCode": {
        #     "code": "1234"
        #   },
        #   "securityCodeLocked": false,
        #   "recoveryKeyLocked": false,
        #   "recoveryKeySupported": true,
        #   "manageTrustedDevicesLinkName": "appleid.apple.com",
        #   "suppressResend": false,
        #   "authType": "hsa",
        #   "accountLocked": false,
        #   "validationErrors": [{
        #     "code": "-21669",
        #     "title": "Incorrect Verification Code",
        #     "message": "Incorrect verification code."
        #   }]
        # }
        if ex.to_s.include?("verification code") # to have a nicer output
          puts("Error: Incorrect verification code")
          return select_device(r, device_id)
        end

        raise ex
      end

      store_session

      return true
    end

    def store_session
      # If the request was successful, r.body is actually nil
      # The previous request will fail if the user isn't on a team
      # on iTunes Connect, but it still works, so we're good

      # Tell iTC that we are trustworthy (obviously)
      # This will update our local cookies to something new
      # They probably have a longer time to live than the other poor cookies
      # Changed Keys
      # - myacinfo
      # - DES5c148586dfd451e55afb0175f62418f91
      # We actually only care about the DES value

      request(:get) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/2sv/trust")

        update_request_headers(req)
      end
      # This request will fail if the user isn't added to a team on iTC
      # However we don't really care, this request will still return the
      # correct DES... cookie

      self.store_cookie
    end

    # Responsible for setting all required header attributes for the requests
    # to succeed
    def update_request_headers(req)
      req.headers["X-Apple-Id-Session-Id"] = @x_apple_id_session_id
      req.headers["X-Apple-Widget-Key"] = self.itc_service_key
      req.headers["Accept"] = "application/json"
      req.headers["scnt"] = @scnt
    end

    private

    def request_two_factor_code_from_phone_choose(phone_numbers, code_length)
      puts("Please select a trusted phone number to send code to:")

      available = phone_numbers.collect do |current|
        current['numberWithDialCode']
      end
      chosen_phone_number = choose(*available)
      phone_id = nil
      phone_numbers.each do |phone|
        phone_id = phone['id'] if phone['numberWithDialCode'] == chosen_phone_number
      end

      phone_number = phone_numbers.find { |phone| phone['numberWithDialCode'] == chosen_phone_number}

      request_code(phone_number)

      code = ask("Please enter the #{code_length} digit code you received at #{chosen_phone_number}:")

      { "securityCode" => { "code" => code.to_s }, "phoneNumber" => { "id" => phone_id }, "mode" => "sms" }.to_json
    end

    def request_two_factor_code_with_google_voice(phone_numbers)
      target_phone_number_suffix = @login_options[:google_number][-2..-1]
      phone_number = phone_numbers.find { |p| p['obfuscatedNumber'].end_with?(target_phone_number_suffix) }
      today = Time.now.strftime "%d-%b-%Y"

      request_code(phone_number)

      # wait a few seconds for the message to arrive
      sleep @login_options[:mail_delay] || 5

      # google voice doesn't have an API we can check, but has the option to forward messages to email
      imap = Net::IMAP.new("imap.gmail.com", 993, true, nil, false)
      imap.login @login_options[:google_account], @login_options[:google_password]
      imap.examine("Inbox")
      uid = imap.uid_search(["SUBJECT", "New text message", "SINCE", today]).last

      raise Tunes::Error.new, "No verification code was sent" unless uid

      bt = imap.uid_fetch(uid, "BODY[TEXT]")[0].attr['BODY[TEXT]']
      code = /Your Apple ID Code is: [0-9]{6}/.match(bt)[0][-6..-1]

      { "securityCode" => { "code" => code.to_s }, "phoneNumber" => { "id" => phone_number['id'] }, "mode" => "sms" }.to_json
    end

    def request_code(chosen_phone_number)
      r = request(:put) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/verify/phone")
        req.headers['Content-Type'] = 'application/json'
        req.body = { "phoneNumber" => { "id" => chosen_phone_number['id'] }, "mode" => "sms" }.to_json
        update_request_headers(req)
      end

      # we use `Spaceship::TunesClient.new.handle_itc_response`
      # since this might be from the Dev Portal, but for 2 step
      Spaceship::TunesClient.new.handle_itc_response(r.body)
      puts("Successfully requested text message to #{chosen_phone_number['numberWithDialCode']}")
    end
  end
end
