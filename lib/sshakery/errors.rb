# Location of Sshakery specific errors
module Sshakery::Errors
    # Raised when Sshakery::AuthKeys.save! is called and validations dont pass
    class RecordInvalid < StandardError
    end
end
