require 'test/test_helper'

describe Sshakery do
    it "must be defined" do
        Sshakery::VERSION.wont_be_nil
    end
end
