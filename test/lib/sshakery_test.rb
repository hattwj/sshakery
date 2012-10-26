require 'test/test_helper'
require 'tempfile'
require 'fileutils'

describe Sshakery do

    # create a copy of test data to manipulate
    before do
        @temp = Tempfile.new('nofail')
        src = "#{$dir}/fixtures/sshakery_nofail_fixture.txt" 
        FileUtils.cp src, @temp.path
        @keys = Sshakery.new(@temp.path)
    end

    # close temp file (should autoremove)
    after do
        @temp.close
        @temp.unlink
    end

    it "must load an authorized_keys file" do
        @keys.all.size.wont_be_nil
    end


    it "must be searchable" do
        @keys.find_all_by(:command,'ls').size.must_equal 1
        @keys.find_all_by(:no_X11_forwarding,true).size.must_equal 1
    end
end

