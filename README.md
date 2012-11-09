# Sshakery

Manipulate authorized_keys files

## Installation

Add this line to your application's Gemfile:

    gem 'sshakery'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install sshakery

## Usage

    require 'sshakery'
    
    # instantiate key file object
    keys = Sshakery.new '/path/to/.ssh/authorized_keys'

    # return array of all keys
    all_keys = keys.all

    # return only keys where the note == 'foo'
    somekeys = keys.find_all_by :note=>'foo'

    # add forced command to key
    key.command = 'ls'
    key.save

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
