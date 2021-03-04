module OneLogin
  module RubySaml

    # SAML2 ContactPerson. Auxiliary class to build the ContactPerson of the SP Metadata
    #
    class ContactPerson
      attr_reader :contacts

      # Initializes the ContactPerson and an empty array as contacts
      #
      def initialize
        @contacts = []
      end

      def configure(&block)
        instance_eval(&block)
      end

      # @return [Boolean] True if the ContactPerson object has been initialized and set with the required values
      #                   (has contact)
      def configured?
        @contacts.length > 0
      end

      # Add an ContactPerson
      # @param options [Hash] ContactPerson option values
      #   add_contact(
      #               :contact_type => "Contact type",
      #               :given_name => "Given Name",
      #               :email => "email@email.com"
      #              )
      #
      def add_contact(options = {})
        contacts << options
      end
    end
  end
end
