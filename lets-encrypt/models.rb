module OCI
  module CertificatesManagement::Models
    class VersionStage

      def initialize
      end

      def build_from_hash(attributes)
        return nil unless attributes.is_a?(Hash)

        self.class.swagger_types.each_pair do |key, type|
          if type =~ /^Array<(.*)>/i
            # check to ensure the input is an array given that the the attribute
            # is documented as an array but the input is not
            if attributes[self.class.attribute_map[key]].is_a?(Array)
              public_method("#{key}=").call(
                attributes[self.class.attribute_map[key]]
                  .map { |v| OCI::Internal::Util.convert_to_type(Regexp.last_match(1), v) }
              )
            end
          elsif !attributes[self.class.attribute_map[key]].nil?
            public_method("#{key}=").call(
              OCI::Internal::Util.convert_to_type(type, attributes[self.class.attribute_map[key]])
            )
          end
          # or else data not found in attributes(hash), not an issue as the data can be optional
        end

        self
      end

    end
  end
end
