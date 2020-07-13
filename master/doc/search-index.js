var searchIndex = JSON.parse('{\
"sentry_contrib_native":{"doc":"sentry-contrib-native","i":[[17,"SDK_USER_AGENT","sentry_contrib_native","SDK Version",null,null],[3,"Breadcrumb","","A Sentry breadcrumb.",null,null],[12,"ty","","Breadcrumb type.",0,null],[12,"message","","Breadcrumb message.",0,null],[12,"map","","Breadcrumb content.",0,null],[3,"Event","","A Sentry event.",null,null],[12,"interface","","Event interface.",1,null],[12,"map","","Event content.",1,null],[3,"Uuid","","A Sentry UUID.",null,null],[3,"Options","","The Sentry client options.",null,null],[3,"Shutdown","","Automatically shuts down the Sentry client on drop.",null,null],[3,"Dsn","","Contains the pieces that are needed to build correct…",null,null],[3,"Parts","","[`Parts`] aquired from [`Dsn::into_parts`].",null,null],[12,"auth","","The auth header value",2,null],[12,"url","","The full URL to send envelopes to",2,null],[3,"Envelope","","The actual body which transports send to Sentry.",null,null],[3,"RawEnvelope","","Wrapper for the raw Envelope that we should send to Sentry.",null,null],[3,"User","","A Sentry user.",null,null],[4,"Interface","","Sentry event interface.",null,null],[13,"Event","","Plain interface.",3,null],[13,"Message","","Message interface.",3,null],[12,"level","sentry_contrib_native::Interface","Level.",4,null],[12,"logger","","Logger.",4,null],[12,"text","","Message text.",4,null],[4,"Message","sentry_contrib_native","Message received for custom logger.",null,null],[13,"Utf8","","Message could be parsed into a valid UTF-8 [`String`].",5,null],[13,"Raw","","Message could not be parsed into a valid UTF-8 [`String`]…",5,null],[4,"TransportError","","Sentry errors.",null,null],[13,"UrlParse","","Failed to parse DSN URL.",6,null],[13,"Scheme","","DSN doesn\'t have a http(s) scheme.",6,null],[13,"Username","","DSN has no username.",6,null],[13,"ProjectID","","DSN has no project ID.",6,null],[13,"Host","","DSN has no host.",6,null],[4,"TransportShutdown","","The return from [`Transport::shutdown`], which determines…",null,null],[13,"Success","","The custom transport was able to send all requests in the…",7,null],[13,"TimedOut","","One or more requests could not be sent in the specified…",7,null],[4,"Value","","Represents a Sentry protocol value.",null,null],[13,"Null","","Null value.",8,null],[13,"Bool","","Boolean.",8,null],[13,"Int","","Integer.",8,null],[13,"Double","","Double.",8,null],[13,"String","","String.",8,null],[13,"List","","List.",8,null],[13,"Map","","Map.",8,null],[4,"Error","","Errors for this crate.",null,null],[13,"SampleRateRange","","Sample rate outside of allowed range.",9,null],[13,"Init","","Failed to initialize Sentry.",9,null],[13,"ListRemove","","Failed to remove value from list by index.",9,null],[13,"MapRemove","","Failed to remove value from map.",9,null],[13,"TryConvert","","Failed to convert to given type.",9,null],[13,"Fingerprints","","List of fingerprints is too long.",9,null],[13,"Transport","","Failed at custom transport.",9,null],[4,"Level","","Sentry event level.",null,null],[13,"Debug","","Debug.",10,null],[13,"Info","","Info.",10,null],[13,"Warning","","Warning.",10,null],[13,"Error","","Error.",10,null],[13,"Fatal","","Fatal.",10,null],[4,"Consent","","The state of user consent.",null,null],[13,"Unknown","","Unknown.",11,null],[13,"Revoked","","Revoked.",11,null],[13,"Given","","Given.",11,null],[5,"set_hook","","Panic handler to send an [`Event`] with the current…",null,[[["box",3],["box",3],["option",4],["option",4]]]],[5,"shutdown","","Shuts down the Sentry client and forces transports to…",null,[[]]],[5,"clear_modulecache","","Clears the internal module cache.",null,[[]]],[5,"set_user_consent","","Resets the user consent (back to unknown).",null,[[["consent",4]]]],[5,"user_consent","","Checks the current state of user consent.",null,[[],["consent",4]]],[5,"remove_user","","Removes a user.",null,[[]]],[5,"set_tag","","Sets a tag.",null,[[["string",3],["into",8]]]],[5,"remove_tag","","Removes the tag with the specified `key`.",null,[[["string",3],["into",8]]]],[5,"set_extra","","Sets extra information.",null,[[["value",4],["into",8],["string",3],["into",8]]]],[5,"remove_extra","","Removes the extra with the specified `key`.",null,[[["string",3],["into",8]]]],[5,"set_context","","Sets a context object.",null,[[["into",8],["into",8],["map",8],["string",3],["value",4]]]],[5,"remove_context","","Removes the context object with the specified key.",null,[[["string",3],["into",8]]]],[5,"set_fingerprint","","Sets the event fingerprint.",null,[[["intoiterator",8]],[["result",4],["error",4]]]],[5,"remove_fingerprint","","Removes the fingerprint.",null,[[]]],[5,"set_transaction","","Sets the transaction.",null,[[["string",3],["into",8]]]],[5,"remove_transaction","","Removes the transaction.",null,[[]]],[5,"set_level","","Sets the event level.",null,[[["level",4]]]],[5,"start_session","","Starts a new session.",null,[[]]],[5,"end_session","","Ends a session.",null,[[]]],[11,"new","","Creates a new Sentry breadcrumb.",0,[[["string",3],["option",4]]]],[11,"insert","","Inserts a key-value pair into the [`Breadcrumb`].",0,[[["value",4],["into",8],["string",3],["into",8]]]],[11,"add","","Adds the [`Breadcrumb`] to be sent in case of an…",0,[[]]],[11,"new","","Creates a new Sentry event.",1,[[]]],[11,"new_message","","Creates a new Sentry message event.",1,[[["into",8],["option",4],["level",4],["string",3]]]],[11,"insert","","Inserts a key-value pair into the [`Event`].",1,[[["value",4],["into",8],["string",3],["into",8]]]],[11,"add_stacktrace","","Adds a stacktrace with `len` instruction pointers to the…",1,[[]]],[11,"add_exception","","Adds an exception to the [`Event`] along with a stacktrace…",1,[[["into",8],["map",8],["value",4]]]],[11,"capture","","Sends the [`Event`].",1,[[],["uuid",3]]],[11,"new","","Creates a new empty Sentry UUID.",12,[[]]],[11,"from_bytes","","Creates a new empty UUID with the given `bytes`.",12,[[]]],[11,"into_bytes","","Returns the bytes of the [`Uuid`].",12,[[]]],[11,"as_bytes","","Yield the bytes of the [`Uuid`].",12,[[]]],[11,"to_plain","","Yield the UUID without dashes.",12,[[],["string",3]]],[11,"new","","Creates new Sentry client options.",13,[[]]],[11,"set_transport","","Sets a custom transport. This only affects events sent…",13,[[["fnonce",8],["sync",8],["send",8]]]],[11,"set_before_send","","Sets a callback that is triggered before sending an event…",13,[[["box",3],["beforesend",8],["into",8]]]],[11,"set_dsn","","Sets the DSN.",13,[[["string",3],["into",8]]]],[11,"dsn","","Gets the DSN.",13,[[],["option",4]]],[11,"set_sample_rate","","Sets the sample rate, which should be a [`f64`] between…",13,[[],[["result",4],["error",4]]]],[11,"sample_rate","","Gets the sample rate.",13,[[]]],[11,"set_release","","Sets the release.",13,[[["string",3],["into",8]]]],[11,"release","","Gets the release.",13,[[],["option",4]]],[11,"set_environment","","Sets the environment.",13,[[["string",3],["into",8]]]],[11,"environment","","Gets the environment.",13,[[],["option",4]]],[11,"set_distribution","","Sets the distribution.",13,[[["string",3],["into",8]]]],[11,"distribution","","Gets the distribution.",13,[[],["option",4]]],[11,"set_http_proxy","","Configures the http proxy.",13,[[["string",3],["into",8]]]],[11,"http_proxy","","Returns the configured http proxy.",13,[[],["option",4]]],[11,"set_ca_certs","","Configures the path to a file containing SSL certificates…",13,[[["string",3],["into",8]]]],[11,"ca_certs","","Returns the configured path for CA certificates.",13,[[],["option",4]]],[11,"set_debug","","Enables or disables debug printing mode.",13,[[]]],[11,"debug","","Returns the current value of the debug flag.",13,[[]]],[11,"set_logger","","Sets a callback that is used for logging purposes when…",13,[[["fn",8],["into",8],["sync",8],["send",8],["box",3]]]],[11,"set_require_user_consent","","Enables or disabled user consent requirements for uploads.",13,[[]]],[11,"require_user_consent","","Returns `true` if user consent is required.",13,[[]]],[11,"set_symbolize_stacktraces","","Enables or disables on-device symbolication of stack traces.",13,[[]]],[11,"symbolize_stacktraces","","Returns `true` if on-device symbolication of stack traces…",13,[[]]],[11,"add_attachment","","Adds a new attachment to be sent along.",13,[[["into",8],["into",8],["pathbuf",3],["string",3]]]],[11,"set_handler_path","","Sets the path to the crashpad handler if the crashpad…",13,[[["pathbuf",3],["into",8]]]],[11,"set_database_path","","Sets the path to the Sentry database directory.",13,[[["pathbuf",3],["into",8]]]],[11,"set_system_crash_reporter","","Enables forwarding to the system crash reporter. Disabled…",13,[[]]],[11,"init","","Initializes the Sentry SDK with the specified options.…",13,[[],[["error",4],["shutdown",3],["result",4]]]],[11,"forget","","Disable automatic shutdown. Call [`shutdown`] manually to…",14,[[]]],[11,"shutdown","","Manually shutdown.",14,[[]]],[11,"serialize","","Serialize a [`RawEnvelope`] into an [`Envelope`].",15,[[],["envelope",3]]],[11,"event","","Yields the event that is being sent in the form of a…",15,[[],["value",4]]],[11,"to_request","","Constructs a HTTP request for the provided [`RawEnvelope`]…",15,[[["dsn",3]],["request",6]]],[11,"as_bytes","","Get underlying data as `&[u8]`.",16,[[]]],[11,"into_request","","Constructs a HTTP request for the provided…",16,[[["dsn",3]],["request",6]]],[11,"new","","Creates a new [`Dsn`] from a [`str`].",17,[[],[["result",4],["error",4]]]],[11,"auth","","The auth header value.",17,[[]]],[11,"url","","The full URL to send envelopes to.",17,[[]]],[11,"into_parts","","Consume [`Dsn`] and return it\'s parts.",17,[[],["parts",3]]],[11,"to_headers","","Yields a [`HeaderMap`] to build a correct HTTP request…",17,[[],["headermap",3]]],[11,"new","","Creates a new user.",18,[[]]],[11,"insert","","Inserts a key-value pair into the [`User`].",18,[[["value",4],["into",8],["string",3],["into",8]]]],[11,"set","","Sets the specified user.",18,[[]]],[11,"new","","Creates a new Sentry value.",8,[[["into",8]]]],[11,"is_null","","Returns `true` if `self` is [`Value::Null`].",8,[[]]],[11,"as_null","","Returns [`Some`] if `self` is [`Value::Null`].",8,[[],["option",4]]],[11,"into_null","","Returns [`Ok`] if `self` is [`Value::Null`].",8,[[],[["result",4],["error",4]]]],[11,"is_bool","","Returns `true` if `self` is [`Value::Bool`].",8,[[]]],[11,"as_bool","","Returns [`Some`] with the inner value if `self` is…",8,[[],["option",4]]],[11,"as_mut_bool","","Returns [`Some`] with the inner value if `self` is…",8,[[],["option",4]]],[11,"into_bool","","Returns [`Ok`] with the inner value if `self` is…",8,[[],[["result",4],["error",4]]]],[11,"is_int","","Returns `true` if `self` is [`Value::Int`].",8,[[]]],[11,"as_int","","Returns [`Some`] with the inner value if `self` is…",8,[[],["option",4]]],[11,"as_mut_int","","Returns [`Some`] with the inner value if `self` is…",8,[[],["option",4]]],[11,"into_int","","Returns [`Ok`] with the inner value if `self` is…",8,[[],[["error",4],["result",4]]]],[11,"is_double","","Returns `true` if `self` is [`Value::Double`].",8,[[]]],[11,"as_double","","Returns [`Some`] with the inner value if `self` is…",8,[[],["option",4]]],[11,"as_mut_double","","Returns [`Some`] with the inner value if `self` is…",8,[[],["option",4]]],[11,"into_double","","Returns [`Ok`] with the inner value if `self` is…",8,[[],[["result",4],["error",4]]]],[11,"is_string","","Returns `true` if `self` is [`Value::String`].",8,[[]]],[11,"as_str","","Returns [`Some`] with the inner value if `self` is…",8,[[],["option",4]]],[11,"as_mut_str","","Returns [`Some`] with the inner value if `self` is…",8,[[],["option",4]]],[11,"into_string","","Returns [`Ok`] with the inner value if `self` is…",8,[[],[["result",4],["string",3],["error",4]]]],[11,"is_list","","Returns `true` if `self` is [`Value::List`].",8,[[]]],[11,"as_list","","Returns [`Some`] with the inner value if `self` is…",8,[[],[["option",4],["vec",3]]]],[11,"as_mut_list","","Returns [`Some`] with the inner value if `self` is…",8,[[],[["option",4],["vec",3]]]],[11,"into_list","","Returns [`Ok`] with the inner value if `self` is…",8,[[],[["result",4],["vec",3],["error",4]]]],[11,"is_map","","Returns `true` if `self` is [`Value::Map`].",8,[[]]],[11,"as_map","","Returns [`Some`] with the inner value if `self` is…",8,[[],[["btreemap",3],["option",4]]]],[11,"as_mut_map","","Returns [`Some`] with the inner value if `self` is…",8,[[],[["btreemap",3],["option",4]]]],[11,"into_map","","Returns [`Ok`] with the inner value if `self` is…",8,[[],[["result",4],["btreemap",3],["error",4]]]],[6,"Request","","The [`http::Request`] request your [`Transport`] is…",null,null],[17,"API_VERSION","","Version of the Sentry API we can communicate with, AFAICT…",null,null],[17,"ENVELOPE_MIME","","The MIME type for Sentry envelopes.",null,null],[8,"BeforeSend","","Trait to help pass data to [`Options::set_before_send`].",null,null],[10,"before_send","","Before send callback.",19,[[["value",4]],["value",4]]],[8,"Map","","Convenience trait to simplify passing a [`Value::Map`].",null,null],[8,"Transport","","Trait used to define a custom transport that Sentry can…",null,null],[10,"send","","Sends the specified Envelope to a Sentry service.",20,[[["rawenvelope",3]]]],[11,"shutdown","","Shuts down the transport worker. The worker should try to…",20,[[["box",3],["duration",3]],["shutdown",4]]],[11,"from","","",0,[[]]],[11,"into","","",0,[[]]],[11,"to_owned","","",0,[[]]],[11,"clone_into","","",0,[[]]],[11,"try_from","","",0,[[],["result",4]]],[11,"try_into","","",0,[[],["result",4]]],[11,"borrow","","",0,[[]]],[11,"borrow_mut","","",0,[[]]],[11,"type_id","","",0,[[],["typeid",3]]],[11,"from","","",1,[[]]],[11,"into","","",1,[[]]],[11,"to_owned","","",1,[[]]],[11,"clone_into","","",1,[[]]],[11,"try_from","","",1,[[],["result",4]]],[11,"try_into","","",1,[[],["result",4]]],[11,"borrow","","",1,[[]]],[11,"borrow_mut","","",1,[[]]],[11,"type_id","","",1,[[],["typeid",3]]],[11,"from","","",12,[[]]],[11,"into","","",12,[[]]],[11,"to_owned","","",12,[[]]],[11,"clone_into","","",12,[[]]],[11,"to_string","","",12,[[],["string",3]]],[11,"try_from","","",12,[[],["result",4]]],[11,"try_into","","",12,[[],["result",4]]],[11,"borrow","","",12,[[]]],[11,"borrow_mut","","",12,[[]]],[11,"type_id","","",12,[[],["typeid",3]]],[11,"from","","",13,[[]]],[11,"into","","",13,[[]]],[11,"try_from","","",13,[[],["result",4]]],[11,"try_into","","",13,[[],["result",4]]],[11,"borrow","","",13,[[]]],[11,"borrow_mut","","",13,[[]]],[11,"type_id","","",13,[[],["typeid",3]]],[11,"from","","",14,[[]]],[11,"into","","",14,[[]]],[11,"to_owned","","",14,[[]]],[11,"clone_into","","",14,[[]]],[11,"try_from","","",14,[[],["result",4]]],[11,"try_into","","",14,[[],["result",4]]],[11,"borrow","","",14,[[]]],[11,"borrow_mut","","",14,[[]]],[11,"type_id","","",14,[[],["typeid",3]]],[11,"from","","",17,[[]]],[11,"into","","",17,[[]]],[11,"to_owned","","",17,[[]]],[11,"clone_into","","",17,[[]]],[11,"try_from","","",17,[[],["result",4]]],[11,"try_into","","",17,[[],["result",4]]],[11,"borrow","","",17,[[]]],[11,"borrow_mut","","",17,[[]]],[11,"type_id","","",17,[[],["typeid",3]]],[11,"from","","",2,[[]]],[11,"into","","",2,[[]]],[11,"to_owned","","",2,[[]]],[11,"clone_into","","",2,[[]]],[11,"try_from","","",2,[[],["result",4]]],[11,"try_into","","",2,[[],["result",4]]],[11,"borrow","","",2,[[]]],[11,"borrow_mut","","",2,[[]]],[11,"type_id","","",2,[[],["typeid",3]]],[11,"from","","",16,[[]]],[11,"into","","",16,[[]]],[11,"try_from","","",16,[[],["result",4]]],[11,"try_into","","",16,[[],["result",4]]],[11,"borrow","","",16,[[]]],[11,"borrow_mut","","",16,[[]]],[11,"type_id","","",16,[[],["typeid",3]]],[11,"from","","",15,[[]]],[11,"into","","",15,[[]]],[11,"try_from","","",15,[[],["result",4]]],[11,"try_into","","",15,[[],["result",4]]],[11,"borrow","","",15,[[]]],[11,"borrow_mut","","",15,[[]]],[11,"type_id","","",15,[[],["typeid",3]]],[11,"from","","",18,[[]]],[11,"into","","",18,[[]]],[11,"to_owned","","",18,[[]]],[11,"clone_into","","",18,[[]]],[11,"try_from","","",18,[[],["result",4]]],[11,"try_into","","",18,[[],["result",4]]],[11,"borrow","","",18,[[]]],[11,"borrow_mut","","",18,[[]]],[11,"type_id","","",18,[[],["typeid",3]]],[11,"from","","",3,[[]]],[11,"into","","",3,[[]]],[11,"to_owned","","",3,[[]]],[11,"clone_into","","",3,[[]]],[11,"try_from","","",3,[[],["result",4]]],[11,"try_into","","",3,[[],["result",4]]],[11,"borrow","","",3,[[]]],[11,"borrow_mut","","",3,[[]]],[11,"type_id","","",3,[[],["typeid",3]]],[11,"from","","",5,[[]]],[11,"into","","",5,[[]]],[11,"to_owned","","",5,[[]]],[11,"clone_into","","",5,[[]]],[11,"to_string","","",5,[[],["string",3]]],[11,"try_from","","",5,[[],["result",4]]],[11,"try_into","","",5,[[],["result",4]]],[11,"borrow","","",5,[[]]],[11,"borrow_mut","","",5,[[]]],[11,"type_id","","",5,[[],["typeid",3]]],[11,"from","","",6,[[]]],[11,"into","","",6,[[]]],[11,"to_string","","",6,[[],["string",3]]],[11,"try_from","","",6,[[],["result",4]]],[11,"try_into","","",6,[[],["result",4]]],[11,"borrow","","",6,[[]]],[11,"borrow_mut","","",6,[[]]],[11,"type_id","","",6,[[],["typeid",3]]],[11,"from","","",7,[[]]],[11,"into","","",7,[[]]],[11,"to_owned","","",7,[[]]],[11,"clone_into","","",7,[[]]],[11,"try_from","","",7,[[],["result",4]]],[11,"try_into","","",7,[[],["result",4]]],[11,"borrow","","",7,[[]]],[11,"borrow_mut","","",7,[[]]],[11,"type_id","","",7,[[],["typeid",3]]],[11,"from","","",8,[[]]],[11,"into","","",8,[[]]],[11,"to_owned","","",8,[[]]],[11,"clone_into","","",8,[[]]],[11,"try_from","","",8,[[],["result",4]]],[11,"try_into","","",8,[[],["result",4]]],[11,"borrow","","",8,[[]]],[11,"borrow_mut","","",8,[[]]],[11,"type_id","","",8,[[],["typeid",3]]],[11,"from","","",9,[[]]],[11,"into","","",9,[[]]],[11,"to_string","","",9,[[],["string",3]]],[11,"try_from","","",9,[[],["result",4]]],[11,"try_into","","",9,[[],["result",4]]],[11,"borrow","","",9,[[]]],[11,"borrow_mut","","",9,[[]]],[11,"type_id","","",9,[[],["typeid",3]]],[11,"from","","",10,[[]]],[11,"into","","",10,[[]]],[11,"to_owned","","",10,[[]]],[11,"clone_into","","",10,[[]]],[11,"to_string","","",10,[[],["string",3]]],[11,"try_from","","",10,[[],["result",4]]],[11,"try_into","","",10,[[],["result",4]]],[11,"borrow","","",10,[[]]],[11,"borrow_mut","","",10,[[]]],[11,"type_id","","",10,[[],["typeid",3]]],[11,"from","","",11,[[]]],[11,"into","","",11,[[]]],[11,"to_owned","","",11,[[]]],[11,"clone_into","","",11,[[]]],[11,"try_from","","",11,[[],["result",4]]],[11,"try_into","","",11,[[],["result",4]]],[11,"borrow","","",11,[[]]],[11,"borrow_mut","","",11,[[]]],[11,"type_id","","",11,[[],["typeid",3]]],[11,"drop","","",13,[[]]],[11,"drop","","",14,[[]]],[11,"drop","","",15,[[]]],[11,"drop","","",16,[[]]],[11,"as_ref","","",12,[[]]],[11,"as_ref","","",16,[[]]],[11,"from","","",12,[[]]],[11,"from","","",6,[[["parseerror",4]]]],[11,"from","","",6,[[["infallible",4]]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[["string",3]]]],[11,"from","","",8,[[]]],[11,"from","","",8,[[["vec",3]]]],[11,"from","","",8,[[["vec",3]]]],[11,"from","","",8,[[["btreemap",3]]]],[11,"from","","",8,[[]]],[11,"from","","",9,[[["transporterror",4]]]],[11,"from","","",9,[[["infallible",4]]]],[11,"clone","","",0,[[],["breadcrumb",3]]],[11,"clone","","",1,[[],["event",3]]],[11,"clone","","",3,[[],["interface",4]]],[11,"clone","","",12,[[],["uuid",3]]],[11,"clone","","",5,[[],["message",4]]],[11,"clone","","",14,[[],["shutdown",3]]],[11,"clone","","",7,[[],["shutdown",4]]],[11,"clone","","",17,[[],["dsn",3]]],[11,"clone","","",2,[[],["parts",3]]],[11,"clone","","",18,[[],["user",3]]],[11,"clone","","",8,[[],["value",4]]],[11,"clone","","",10,[[],["level",4]]],[11,"clone","","",11,[[],["consent",4]]],[11,"default","","",0,[[]]],[11,"default","","",1,[[]]],[11,"default","","",12,[[]]],[11,"default","","",13,[[]]],[11,"default","","",18,[[]]],[11,"default","","",8,[[]]],[11,"cmp","","",3,[[["interface",4]],["ordering",4]]],[11,"cmp","","",12,[[],["ordering",4]]],[11,"cmp","","",5,[[["message",4]],["ordering",4]]],[11,"cmp","","",14,[[["shutdown",3]],["ordering",4]]],[11,"cmp","","",7,[[["shutdown",4]],["ordering",4]]],[11,"cmp","","",15,[[["rawenvelope",3]],["ordering",4]]],[11,"cmp","","",16,[[["envelope",3]],["ordering",4]]],[11,"cmp","","",17,[[["dsn",3]],["ordering",4]]],[11,"cmp","","",2,[[["parts",3]],["ordering",4]]],[11,"cmp","","",10,[[["level",4]],["ordering",4]]],[11,"cmp","","",11,[[["consent",4]],["ordering",4]]],[11,"eq","","",0,[[["breadcrumb",3]]]],[11,"ne","","",0,[[["breadcrumb",3]]]],[11,"eq","","",1,[[["event",3]]]],[11,"ne","","",1,[[["event",3]]]],[11,"eq","","",3,[[["interface",4]]]],[11,"ne","","",3,[[["interface",4]]]],[11,"eq","","",12,[[]]],[11,"eq","","",5,[[["message",4]]]],[11,"ne","","",5,[[["message",4]]]],[11,"eq","","",13,[[]]],[11,"eq","","",14,[[["shutdown",3]]]],[11,"eq","","",6,[[["error",4]]]],[11,"ne","","",6,[[["error",4]]]],[11,"eq","","",7,[[["shutdown",4]]]],[11,"eq","","",15,[[["rawenvelope",3]]]],[11,"ne","","",15,[[["rawenvelope",3]]]],[11,"eq","","",16,[[["envelope",3]]]],[11,"ne","","",16,[[["envelope",3]]]],[11,"eq","","",17,[[["dsn",3]]]],[11,"ne","","",17,[[["dsn",3]]]],[11,"eq","","",2,[[["parts",3]]]],[11,"ne","","",2,[[["parts",3]]]],[11,"eq","","",18,[[["user",3]]]],[11,"ne","","",18,[[["user",3]]]],[11,"eq","","",8,[[["value",4]]]],[11,"ne","","",8,[[["value",4]]]],[11,"eq","","",9,[[["error",4]]]],[11,"ne","","",9,[[["error",4]]]],[11,"eq","","",10,[[["level",4]]]],[11,"eq","","",11,[[["consent",4]]]],[11,"partial_cmp","","",0,[[["breadcrumb",3]],[["option",4],["ordering",4]]]],[11,"lt","","",0,[[["breadcrumb",3]]]],[11,"le","","",0,[[["breadcrumb",3]]]],[11,"gt","","",0,[[["breadcrumb",3]]]],[11,"ge","","",0,[[["breadcrumb",3]]]],[11,"partial_cmp","","",1,[[["event",3]],[["option",4],["ordering",4]]]],[11,"lt","","",1,[[["event",3]]]],[11,"le","","",1,[[["event",3]]]],[11,"gt","","",1,[[["event",3]]]],[11,"ge","","",1,[[["event",3]]]],[11,"partial_cmp","","",3,[[["interface",4]],[["option",4],["ordering",4]]]],[11,"lt","","",3,[[["interface",4]]]],[11,"le","","",3,[[["interface",4]]]],[11,"gt","","",3,[[["interface",4]]]],[11,"ge","","",3,[[["interface",4]]]],[11,"partial_cmp","","",12,[[],[["option",4],["ordering",4]]]],[11,"partial_cmp","","",5,[[["message",4]],[["option",4],["ordering",4]]]],[11,"lt","","",5,[[["message",4]]]],[11,"le","","",5,[[["message",4]]]],[11,"gt","","",5,[[["message",4]]]],[11,"ge","","",5,[[["message",4]]]],[11,"partial_cmp","","",14,[[["shutdown",3]],[["option",4],["ordering",4]]]],[11,"partial_cmp","","",7,[[["shutdown",4]],[["option",4],["ordering",4]]]],[11,"partial_cmp","","",15,[[["rawenvelope",3]],[["option",4],["ordering",4]]]],[11,"lt","","",15,[[["rawenvelope",3]]]],[11,"le","","",15,[[["rawenvelope",3]]]],[11,"gt","","",15,[[["rawenvelope",3]]]],[11,"ge","","",15,[[["rawenvelope",3]]]],[11,"partial_cmp","","",16,[[["envelope",3]],[["option",4],["ordering",4]]]],[11,"lt","","",16,[[["envelope",3]]]],[11,"le","","",16,[[["envelope",3]]]],[11,"gt","","",16,[[["envelope",3]]]],[11,"ge","","",16,[[["envelope",3]]]],[11,"partial_cmp","","",17,[[["dsn",3]],[["option",4],["ordering",4]]]],[11,"lt","","",17,[[["dsn",3]]]],[11,"le","","",17,[[["dsn",3]]]],[11,"gt","","",17,[[["dsn",3]]]],[11,"ge","","",17,[[["dsn",3]]]],[11,"partial_cmp","","",2,[[["parts",3]],[["option",4],["ordering",4]]]],[11,"lt","","",2,[[["parts",3]]]],[11,"le","","",2,[[["parts",3]]]],[11,"gt","","",2,[[["parts",3]]]],[11,"ge","","",2,[[["parts",3]]]],[11,"partial_cmp","","",18,[[["user",3]],[["option",4],["ordering",4]]]],[11,"lt","","",18,[[["user",3]]]],[11,"le","","",18,[[["user",3]]]],[11,"gt","","",18,[[["user",3]]]],[11,"ge","","",18,[[["user",3]]]],[11,"partial_cmp","","",8,[[["value",4]],[["option",4],["ordering",4]]]],[11,"lt","","",8,[[["value",4]]]],[11,"le","","",8,[[["value",4]]]],[11,"gt","","",8,[[["value",4]]]],[11,"ge","","",8,[[["value",4]]]],[11,"partial_cmp","","",10,[[["level",4]],[["option",4],["ordering",4]]]],[11,"partial_cmp","","",11,[[["consent",4]],[["option",4],["ordering",4]]]],[11,"deref","","",0,[[]]],[11,"deref","","",1,[[]]],[11,"deref","","",18,[[]]],[11,"deref_mut","","",0,[[]]],[11,"deref_mut","","",1,[[]]],[11,"deref_mut","","",18,[[]]],[11,"fmt","","",0,[[["formatter",3]],["result",6]]],[11,"fmt","","",1,[[["formatter",3]],["result",6]]],[11,"fmt","","",3,[[["formatter",3]],["result",6]]],[11,"fmt","","",12,[[["formatter",3]],["result",6]]],[11,"fmt","","",5,[[["formatter",3]],["result",6]]],[11,"fmt","","",13,[[["formatter",3]],["fmtresult",6]]],[11,"fmt","","",14,[[["formatter",3]],["result",6]]],[11,"fmt","","",6,[[["formatter",3]],["result",6]]],[11,"fmt","","",7,[[["formatter",3]],["result",6]]],[11,"fmt","","",15,[[["formatter",3]],["result",6]]],[11,"fmt","","",16,[[["formatter",3]],["result",6]]],[11,"fmt","","",17,[[["formatter",3]],["result",6]]],[11,"fmt","","",2,[[["formatter",3]],["result",6]]],[11,"fmt","","",18,[[["formatter",3]],["result",6]]],[11,"fmt","","",8,[[["formatter",3]],["result",6]]],[11,"fmt","","",9,[[["formatter",3]],["result",6]]],[11,"fmt","","",10,[[["formatter",3]],["result",6]]],[11,"fmt","","",11,[[["formatter",3]],["result",6]]],[11,"fmt","","",12,[[["formatter",3]],["result",6]]],[11,"fmt","","",5,[[["formatter",3]],["fmtresult",6]]],[11,"fmt","","",6,[[["formatter",3]],["result",6]]],[11,"fmt","","",9,[[["formatter",3]],["result",6]]],[11,"fmt","","",10,[[["formatter",3]],["fmtresult",6]]],[11,"hash","","",3,[[]]],[11,"hash","","",12,[[]]],[11,"hash","","",5,[[]]],[11,"hash","","",14,[[]]],[11,"hash","","",7,[[]]],[11,"hash","","",15,[[]]],[11,"hash","","",16,[[]]],[11,"hash","","",17,[[]]],[11,"hash","","",2,[[]]],[11,"hash","","",10,[[]]],[11,"hash","","",11,[[]]],[11,"try_from","","",17,[[],["result",4]]],[11,"from_str","","",17,[[],["result",4]]],[11,"source","","",6,[[],[["error",8],["option",4]]]],[11,"source","","",9,[[],[["error",8],["option",4]]]],[11,"shutdown","","Shuts down the transport worker. The worker should try to…",20,[[["box",3],["duration",3]],["shutdown",4]]]],"p":[[3,"Breadcrumb"],[3,"Event"],[3,"Parts"],[4,"Interface"],[13,"Message"],[4,"Message"],[4,"TransportError"],[4,"TransportShutdown"],[4,"Value"],[4,"Error"],[4,"Level"],[4,"Consent"],[3,"Uuid"],[3,"Options"],[3,"Shutdown"],[3,"RawEnvelope"],[3,"Envelope"],[3,"Dsn"],[3,"User"],[8,"BeforeSend"],[8,"Transport"]]},\
"sentry_contrib_native_sys":{"doc":"sentry-contrib-native-sys","i":[[3,"Options","sentry_contrib_native_sys","The Sentry Client Options.",null,null],[3,"Uuid","","A UUID",null,null],[12,"bytes","","Bytes of the uuid.",0,null],[3,"Transport","","This represents an interface for user-defined transports.",null,null],[3,"Envelope","","A Sentry Envelope.",null,null],[19,"Value","","Represents a Sentry protocol value.",null,null],[4,"Level","","Sentry levels for events and breadcrumbs.",null,null],[13,"Debug","","Debug",1,null],[13,"Info","","Info",1,null],[13,"Warning","","Warning",1,null],[13,"Error","","Error",1,null],[13,"Fatal","","Fatal",1,null],[4,"ValueType","","Type of a Sentry value.",null,null],[13,"Null","","Null",2,null],[13,"Bool","","Bool",2,null],[13,"Int","","Integer",2,null],[13,"Double","","Double",2,null],[13,"String","","String",2,null],[13,"List","","List",2,null],[13,"Object","","Object",2,null],[4,"UserConsent","","The state of user consent.",null,null],[13,"Unknown","","Unknown",3,null],[13,"Given","","Given",3,null],[13,"Revoked","","Revoked",3,null],[5,"free","","Releases memory allocated from the underlying allocator.",null,null],[5,"value_incref","","Increments the reference count on the value.",null,null],[5,"value_decref","","Decrements the reference count on the value.",null,null],[5,"value_new_null","","Creates a null value.",null,null],[5,"value_new_int32","","Creates a new 32-bit signed integer value.",null,null],[5,"value_new_double","","Creates a new double value.",null,null],[5,"value_new_bool","","Creates a new boolen value.",null,null],[5,"value_new_string","","Creates a new null terminated string.",null,null],[5,"value_new_list","","Creates a new list value.",null,null],[5,"value_new_object","","Creates a new object.",null,null],[5,"value_get_type","","Returns the type of the value passed.",null,null],[5,"value_set_by_key","","Sets a key to a value in the map.",null,null],[5,"value_remove_by_key","","This removes a value from the map by key.",null,null],[5,"value_append","","Appends a value to a list. This moves the ownership of the…",null,null],[5,"value_set_by_index","","Inserts a value into the list at a certain position.",null,null],[5,"value_remove_by_index","","This removes a value from the list by index.",null,null],[5,"value_get_by_key","","Looks up a value in a map by key. If missing a null value…",null,null],[5,"value_get_by_key_owned","","Looks up a value in a map by key. If missing a null value…",null,null],[5,"value_get_by_index","","Looks up a value in a list by index. If missing a null…",null,null],[5,"value_get_by_index_owned","","Looks up a value in a list by index. If missing a null…",null,null],[5,"value_get_length","","Returns the length of the given map or list.",null,null],[5,"value_as_int32","","Converts a value into a 32bit signed integer.",null,null],[5,"value_as_double","","Converts a value into a double value.",null,null],[5,"value_as_string","","Returns the value as c string.",null,null],[5,"value_is_true","","Returns `true` if the value is boolean true.",null,null],[5,"value_new_event","","Creates a new empty event value.",null,null],[5,"value_new_message_event","","Creates a new message event value.",null,null],[5,"value_new_breadcrumb","","Creates a new breadcrumb with a specific type and message.",null,null],[5,"value_to_msgpack","","Serialize a Sentry value to msgpack.",null,null],[5,"event_value_add_stacktrace","","Adds a stacktrace to an event.",null,null],[5,"uuid_nil","","Creates the nil uuid.",null,null],[5,"uuid_as_string","","Formats the uuid into a string buffer.",null,null],[5,"envelope_free","","Frees an envelope.",null,null],[5,"envelope_get_event","","Given an envelope returns the embedded event if there is…",null,null],[5,"envelope_serialize","","Serializes the envelope.",null,null],[5,"transport_new","","Creates a new transport with an initial `send_func`.",null,null],[5,"transport_set_state","","Sets the transport `state`.",null,null],[5,"transport_set_free_func","","Sets the transport hook to free the transport `state`.",null,null],[5,"transport_set_startup_func","","Sets the transport startup hook.",null,null],[5,"transport_set_shutdown_func","","Sets the transport shutdown hook.",null,null],[5,"transport_free","","Generic way to free a transport.",null,null],[5,"options_new","","Creates a new options struct. Can be freed with…",null,null],[5,"options_free","","Deallocates previously allocated Sentry options.",null,null],[5,"options_set_transport","","Sets a transport.",null,null],[5,"options_set_before_send","","Sets the before send callback.",null,null],[5,"options_set_dsn","","Sets the DSN.",null,null],[5,"options_get_dsn","","Gets the DSN.",null,null],[5,"options_set_sample_rate","","Sets the sample rate, which should be a double between…",null,null],[5,"options_get_sample_rate","","Gets the sample rate.",null,null],[5,"options_set_release","","Sets the release.",null,null],[5,"options_get_release","","Gets the release.",null,null],[5,"options_set_environment","","Sets the environment.",null,null],[5,"options_get_environment","","Gets the environment.",null,null],[5,"options_set_dist","","Sets the dist.",null,null],[5,"options_get_dist","","Gets the dist.",null,null],[5,"options_set_http_proxy","","Configures the http proxy.",null,null],[5,"options_get_http_proxy","","Returns the configured http proxy.",null,null],[5,"options_set_ca_certs","","Configures the path to a file containing ssl certificates…",null,null],[5,"options_get_ca_certs","","Returns the configured path for ca certificates.",null,null],[5,"options_set_debug","","Enables or disables debug printing mode.",null,null],[5,"options_get_debug","","Returns the current value of the debug flag.",null,null],[5,"options_set_logger","","Sets the sentry-native logger function. Used for logging…",null,null],[5,"options_set_require_user_consent","","Enables or disabled user consent requirements for uploads.",null,null],[5,"options_get_require_user_consent","","Returns true if user consent is required.",null,null],[5,"options_set_symbolize_stacktraces","","Enables or disables on-device symbolication of stack traces.",null,null],[5,"options_get_symbolize_stacktraces","","Returns true if on-device symbolication of stack traces is…",null,null],[5,"options_add_attachment","","Adds a new attachment to be sent along.",null,null],[5,"options_set_handler_path","","Sets the path to the crashpad handler if the crashpad…",null,null],[5,"options_set_database_path","","Sets the path to the Sentry Database Directory.",null,null],[5,"options_add_attachmentw","","Wide char version of `sentry_options_add_attachment`.",null,null],[5,"options_set_handler_pathw","","Wide char version of `sentry_options_set_handler_path`.",null,null],[5,"options_set_database_pathw","","Wide char version of `sentry_options_set_database_path`",null,null],[5,"options_set_system_crash_reporter_enabled","","Enables forwarding to the system crash reporter. Disabled…",null,null],[5,"init","","Initializes the Sentry SDK with the specified options.",null,null],[5,"shutdown","","Shuts down the Sentry client and forces transports to…",null,null],[5,"clear_modulecache","","Clears the internal module cache.",null,null],[5,"get_options","","Returns the client options.",null,null],[5,"user_consent_give","","Gives user consent.",null,null],[5,"user_consent_revoke","","Revokes user consent.",null,null],[5,"user_consent_reset","","Resets the user consent (back to unknown).",null,null],[5,"user_consent_get","","Checks the current state of user consent.",null,null],[5,"capture_event","","Sends a Sentry event.",null,null],[5,"add_breadcrumb","","Adds the breadcrumb to be sent in case of an event.",null,null],[5,"set_user","","Sets the specified user.",null,null],[5,"remove_user","","Removes a user.",null,null],[5,"set_tag","","Sets a tag.",null,null],[5,"remove_tag","","Removes the tag with the specified key.",null,null],[5,"set_extra","","Sets extra information.",null,null],[5,"remove_extra","","Removes the extra with the specified key.",null,null],[5,"set_context","","Sets a context object.",null,null],[5,"remove_context","","Removes the context object with the specified key.",null,null],[5,"set_fingerprint","","Sets the event fingerprint.",null,null],[5,"remove_fingerprint","","Removes the fingerprint.",null,null],[5,"set_transaction","","Sets the transaction.",null,null],[5,"remove_transaction","","Removes the transaction.",null,null],[5,"set_level","","Sets the event level.",null,null],[5,"start_session","","Starts a new session.",null,null],[5,"end_session","","Ends a session.",null,null],[6,"c_wchar","","Char type for Windows APIs.",null,null],[6,"EventFunction","","Type of the callback for modifying events.",null,null],[6,"LoggerFunction","","Type of the callback for logging debug events.",null,null],[6,"SendEnvelopeFunction","","Type of callback for sending envelopes to a Sentry service",null,null],[6,"StartupFunction","","Type of the callback for starting up a custom transport",null,null],[6,"ShutdownFunction","","Type of the callback for shutting down a custom transport",null,null],[17,"SDK_USER_AGENT","","SDK Version",null,null],[11,"from","","",4,[[]]],[11,"into","","",4,[[]]],[11,"to_owned","","",4,[[]]],[11,"clone_into","","",4,[[]]],[11,"try_from","","",4,[[],["result",4]]],[11,"try_into","","",4,[[],["result",4]]],[11,"borrow","","",4,[[]]],[11,"borrow_mut","","",4,[[]]],[11,"type_id","","",4,[[],["typeid",3]]],[11,"from","","",0,[[]]],[11,"into","","",0,[[]]],[11,"to_owned","","",0,[[]]],[11,"clone_into","","",0,[[]]],[11,"try_from","","",0,[[],["result",4]]],[11,"try_into","","",0,[[],["result",4]]],[11,"borrow","","",0,[[]]],[11,"borrow_mut","","",0,[[]]],[11,"type_id","","",0,[[],["typeid",3]]],[11,"from","","",5,[[]]],[11,"into","","",5,[[]]],[11,"to_owned","","",5,[[]]],[11,"clone_into","","",5,[[]]],[11,"try_from","","",5,[[],["result",4]]],[11,"try_into","","",5,[[],["result",4]]],[11,"borrow","","",5,[[]]],[11,"borrow_mut","","",5,[[]]],[11,"type_id","","",5,[[],["typeid",3]]],[11,"from","","",6,[[]]],[11,"into","","",6,[[]]],[11,"to_owned","","",6,[[]]],[11,"clone_into","","",6,[[]]],[11,"try_from","","",6,[[],["result",4]]],[11,"try_into","","",6,[[],["result",4]]],[11,"borrow","","",6,[[]]],[11,"borrow_mut","","",6,[[]]],[11,"type_id","","",6,[[],["typeid",3]]],[11,"from","","",7,[[]]],[11,"into","","",7,[[]]],[11,"to_owned","","",7,[[]]],[11,"clone_into","","",7,[[]]],[11,"try_from","","",7,[[],["result",4]]],[11,"try_into","","",7,[[],["result",4]]],[11,"borrow","","",7,[[]]],[11,"borrow_mut","","",7,[[]]],[11,"type_id","","",7,[[],["typeid",3]]],[11,"from","","",1,[[]]],[11,"into","","",1,[[]]],[11,"to_owned","","",1,[[]]],[11,"clone_into","","",1,[[]]],[11,"try_from","","",1,[[],["result",4]]],[11,"try_into","","",1,[[],["result",4]]],[11,"borrow","","",1,[[]]],[11,"borrow_mut","","",1,[[]]],[11,"type_id","","",1,[[],["typeid",3]]],[11,"from","","",2,[[]]],[11,"into","","",2,[[]]],[11,"to_owned","","",2,[[]]],[11,"clone_into","","",2,[[]]],[11,"try_from","","",2,[[],["result",4]]],[11,"try_into","","",2,[[],["result",4]]],[11,"borrow","","",2,[[]]],[11,"borrow_mut","","",2,[[]]],[11,"type_id","","",2,[[],["typeid",3]]],[11,"from","","",3,[[]]],[11,"into","","",3,[[]]],[11,"to_owned","","",3,[[]]],[11,"clone_into","","",3,[[]]],[11,"try_from","","",3,[[],["result",4]]],[11,"try_into","","",3,[[],["result",4]]],[11,"borrow","","",3,[[]]],[11,"borrow_mut","","",3,[[]]],[11,"type_id","","",3,[[],["typeid",3]]],[11,"clone","","",4,[[],["options",3]]],[11,"clone","","",7,[[],["value",19]]],[11,"clone","","",0,[[],["uuid",3]]],[11,"clone","","",1,[[],["level",4]]],[11,"clone","","",2,[[],["valuetype",4]]],[11,"clone","","",3,[[],["userconsent",4]]],[11,"clone","","",5,[[],["transport",3]]],[11,"clone","","",6,[[],["envelope",3]]],[11,"fmt","","",4,[[["formatter",3]],["result",6]]],[11,"fmt","","",0,[[["formatter",3]],["result",6]]],[11,"fmt","","",1,[[["formatter",3]],["result",6]]],[11,"fmt","","",2,[[["formatter",3]],["result",6]]],[11,"fmt","","",3,[[["formatter",3]],["result",6]]],[11,"fmt","","",5,[[["formatter",3]],["result",6]]],[11,"fmt","","",6,[[["formatter",3]],["result",6]]]],"p":[[3,"Uuid"],[4,"Level"],[4,"ValueType"],[4,"UserConsent"],[3,"Options"],[3,"Transport"],[3,"Envelope"],[19,"Value"]]}\
}');
addSearchOptions(searchIndex);initSearch(searchIndex);