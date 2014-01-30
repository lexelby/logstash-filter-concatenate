require "logstash/filters/base"
require "logstash/namespace"

# The concatenate filter gloms together messages it receives.  Messages are
# grouped by a key you specify (see the key parameter).  Messages with a given
# key are gathered together, and when a specified time has passed since any
# messages were received, the concatenated message is produced.  You can also
# specify a time after which the concatenated message will be flushed even if
# recent messages were received.

class LogStash::Filters::Concatenate < LogStash::Filters::Base

    # The name to use in configuration files.
    config_name "concatenate"

    # New plugins should start life at milestone 1.
    milestone 1

    # The key used to identify events. Events with the same key will be
    # concatenated together.  Field substitutions are allowed, so you can combine
    # multiple fields.
    config :key, :validate => :string, :required => true

    # If no messages are received for at least this many seconds for a given key,
    # the concatenated message for that key is flushed.
    config :min_flush_time, :validate => :number, :default => 10, :required => false

    # This specifies the maximum amount of time you're willing to let a
    # concatenated message build up.  After this amount of time has elapsed, the
    # concatenated message will be produced even if messages for this key have
    # been received within the last min_flush_time seconds.
    config :max_flush_time, :validate => :number, :default => 60, :required => false

    # The maximum number of unique keys allowed.  This is used as a memory control
    # mechanism, in case a highly variable key is specified.  You shoudln't rely
    # on this; it's just here to make sure that memory usage does not grow
    # without bound.
    config :max_keys, :validate => :number, :default => 100000, :required => false

    # Performs initialization of the filter.
    public
    def register
        @threadsafe = false
        @concatenated_events = {}
    end # def register

    public
    def filter(event)

        # Return nothing unless there's an actual filter event
        return unless filter?(event)

        now = Time.now
        key = event.sprintf(@key)

        if @concatenated_events.include?(key) then
            concat = @concatenated_events[key]
            concat[:last_seen] = now
            concat[:event].append(event)
        else
            @concatenated_events[key] = { :first_seen => now,
                                          :last_seen => now,
                                          :event => event }
        end

        event.cancel
    end # def filter

    def flush
        events = []

        now = Time.now

        @concatenated_events.each do |key, entry|
            if now - entry[:last_seen] > @min_flush_time or
               now - entry[:first_seen] > @max_flush_time then
                    entry[:event].uncancel
                    entry[:event].filter_matched
                    events << entry[:event]
                    @concatenated_events.delete(key)
            end
        end

        return events
    end # def flush
end # class LogStash::Filters::Concatenate
