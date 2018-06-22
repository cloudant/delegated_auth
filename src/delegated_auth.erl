-module(delegated_auth).

-compile(tuple_calls).

-include_lib("couch/include/couch_db.hrl").
-export([handle_delegated_auth_req/1, delegated_authentication_handler/1]).

-import(chttpd, [send_json/3, send_method_not_allowed/2]).

%% Return a token
handle_delegated_auth_req(#httpd{method='POST', mochi_req=MochiReq}=Req) ->
    %% cloudant_auth should verify admin access
    {Name, Roles} = case MochiReq:get_primary_header_value("content-type") of
        "application/x-www-form-urlencoded" ->
            ReqBody = MochiReq:recv_body(),
            Form = [{?l2b(K),?l2b(V)} || {K,V} <- mochiweb_util:parse_qs(ReqBody)],
            Name0 = validate_name(couch_util:get_value(<<"name">>, Form)),
            Roles0 = validate_roles(proplists:get_all_values(<<"roles">>, Form)),
            {Name0, Roles0};
        "application/json" ->
            couch_httpd:validate_ctype(Req, "application/json"),
            {Props} = couch_httpd:json_body(Req),
            Name0 = validate_name(couch_util:get_value(<<"name">>, Props)),
            Roles0 = validate_roles(couch_util:get_value(<<"roles">>, Props, [])),
            {Name0, Roles0};
        _ ->
            throw({bad_request, <<"Unexpected content type">>})
    end,
    Cookie = make_cookie(Name, Roles),
    send_json(Req, 200, {[{ok, true}, {cookie, Cookie},
                          {name, ?l2b(Name)}, {roles, ?l2b(Roles)}]});
handle_delegated_auth_req(Req) ->
    send_method_not_allowed(Req, "POST").

%% Look for token
delegated_authentication_handler(#httpd{mochi_req=MochiReq}=Req) ->
    case MochiReq:get_cookie_value("DelegatedAuth") of
    undefined ->
        Req;
    [] ->
        Req;
    Cookie ->
        [User, Roles, TimeStr | MacParts] = try
            DelegatedAuth = couch_util:decodeBase64Url(Cookie),
            re:split(?b2l(DelegatedAuth), ":", [{return, list}])
        catch
            _:_Error ->
                throw({bad_request, <<"Malformed DelegatedAuth cookie.">>})
        end,
        CurrentTime = make_cookie_time(),
        Secret = ensure_delegated_auth_secret(),
        ExpectedMac = crypto:hmac(sha, Secret, User ++ ":" ++ Roles ++ ":" ++ TimeStr),
        ActualMac = ?l2b(string:join(MacParts, ":")),
        Timeout = timeout(),
        case (catch erlang:list_to_integer(TimeStr, 16)) of
            TimeStamp when CurrentTime < TimeStamp + Timeout ->
                case couch_util:verify(ExpectedMac, ActualMac) of
                    true ->
                        Req#httpd{user_ctx=#user_ctx{
                            name=?l2b(User),
                            roles=[?l2b(Role) || Role <- string:tokens(Roles, ",")]}};
                    _Else ->
                        Req
                end;
            _Else ->
                Req
        end
    end.

validate_name(Name) when is_binary(Name) ->
    ?b2l(Name);
validate_name(_Name) ->
    throw({bad_request, <<"Malformed or missing 'name'">>}).

validate_roles(Roles) ->
    validate_roles(Roles, []).

validate_roles([], Acc) ->
    string:join(Acc, ",");
validate_roles([Role|Rest], Acc) when is_binary(Role) ->
    validate_roles(Rest, [?b2l(Role)|Acc]);
validate_roles(_, _Acc) ->
    throw({bad_request, <<"Malformed roles">>}).

make_cookie(Name, "") ->
    make_cookie(Name, ",");
make_cookie(Name, Roles) ->
    TimeStamp = make_cookie_time(),
    Secret = ensure_delegated_auth_secret(),
    SessionData = Name ++ ":" ++ Roles ++ ":" ++ erlang:integer_to_list(TimeStamp, 16),
    Mac = crypto:hmac(sha, Secret, SessionData),
    {"Set-Cookie", CookieValue} = mochiweb_cookies:cookie("DelegatedAuth",
        couch_util:encodeBase64Url(SessionData ++ ":" ++ ?b2l(Mac)),
        [{path, "/"}, {max_age, timeout()}]),
    ?l2b(CookieValue).

make_cookie_time() ->
    {NowMS, NowS, _} = erlang:now(),
    NowMS * 1000000 + NowS.

ensure_delegated_auth_secret() ->
    case config:get("delegated_auth", "secret", undefined) of
        undefined ->
            throw({bad_request, <<"Server not configured for delegated authentication">>});
        Secret -> Secret
    end.

%% timeout defaults to 30 days.
timeout() ->
    list_to_integer(config:get("delegated_auth", "timeout", "2592000")).

