package MiddleMan::OAuthHandler;

=head1 NAME

MiddleMan::OAuthHandler - Deal with OAuth for commandline tools

=head1 SYNOPSIS

   use MiddleMan::OauthHandler;
   
   # device code:
   my $oauth = MiddleMan::OauthHandler->new({
     conf => {
       client_id              => 'myid',
       client_secret          => 'mysecret',
       code_endpoint          => 'https://foo.com/code',
       code_token_endpoint    => 'https://foo.com/code/token',
       callback_sub           => sub { print($_[0]); },
       token_string           => 'mystr',
     }
   });

   # browser auth
   my $oauth = MiddleMan::OauthHandler->new({
     conf => {
       client_id              => 'myid',
       client_secret          => 'mysecret',
       authorization_endpoint => 'https://foo.com/authorize',
       token_endpoint         => 'https://foo.com/token',
       service_name           => 'trakt_api',
       token_string           => 'mystr',
     }
   });

=head1 DESCRIPTION



=cut

use Moo;
use LWP::Authen::OAuth2;
use LWP::Authen::OAuth2::AccessToken::Bearer;
use LWP::UserAgent;
use JSON qw/encode_json decode_json/;
use Future::Utils qw/repeat/;
use Try::Tiny;
use Data::Dumper;

has 'middleman_service_name' => (is => 'ro');
has 'middleman_host'   => (is => 'rw', default => sub { 'http://desert-island.me.uk/oauth' });
has 'middleman_email' => (is => 'rw');
has 'conf'    => (is => 'ro');
has '_ua'     => (is => 'ro', default => sub { LWP::UserAgent->new(); });
has '_oauth'  => (is => 'lazy', default => sub {
    my ($self) = @_;
    LWP::Authen::OAuth2->new(%{ $self->conf });
});
has 'callback_sub' => (is => 'ro');

=head2 authenticate

Creates an L<LWP::Authen::OAuth2> object using the config from the
caller, returns it if the token_string was provided, and not expired
yet.

If caller specified B<code_endpoint> uri, then use device code auth to
login, and return OAuth2 object. L</callback_str> will be used to
return the urls needed to enter the code.

Else use normal browser auth, using L</callback_str> to output urls to
visit.

=cut

sub authenticate {
    my ($self) = @_;

    # this loads using the ole token_string (assuming caller saved it
    # and passed it back)
    my $oa = $self->_oauth();
    if($oa->access_token && $oa->access_token->expires_in > 20) {
        # not expired yet? just use it
        return $oa;
    }
    
    if($self->conf->{code_endpoint}) {
        ## We're using a device code fetch (see https://trakt.docs.apiary.io/#reference/authentication-oauth/authorize/authorize-application)
        return $self->device_code_auth();
    } else {
        ## Standard full oauth fetch:
        return $self->auth_full();
    }
}

sub auth_full {
    my ($self) = @_;
    # Create email/service combo on the oauth service (get back an id)
    my $ua = $self->_ua();
    my $res = $ua->post($self->middleman_host . '/new',
                        Content => encode_json({ email => $self->middleman_email, service => $self->middleman_service_name }) );

    if(!$res->is_success) {
        die $res->status_line;
    }

    my $new_id = $res->decoded_content();
    if(!$new_id || $new_id =~ /\D/) {
        die "Didn't get a new id from oauth/new!";
    }

    my $oauth2 = LWP::Authen::OAuth2->new(
        client_id => $self->conf->{client_id},
        client_secret => $self->conf->{client_secret},
        authorization_endpoint => $self->conf->{authorization_endpoint},
        token_endpoint => $self->conf->{token_endpoint},
        redirect_uri => $self->middleman_host ."/callback/$new_id",
        request_required_params => [qw/grant_type client_id client_secret code redirect_uri/],
        #scope => 'basic+ageless',
        );

    my $url = $oauth2->authorization_url();

    print "Auth: ", $self->service, " $url\n";

    my $result = $self->poll_response('get', {}, $self->middleman_host ."/get/$new_id", 1, 60*10);
    my $code = $result ? decode_json($result)->{code} : '';

    $oauth2->request_tokens(
        code => $code,
        redirect_uri => $self->middleman_host ."/callback/$new_id"
        );

    ## We should really be returning the OAuth2 object, which calling
    ## code can call "request" / put / post / delete / get / head on?
    ## (this also refreshes the token

    #print $oauth2->token_string;
    return decode_json($oauth2->token_string);
}

=head2 poll_response

Generic polling for responses method, poll the given B<$uri> for
B<$stop_after> seconds, with maximum B<$interval> seconds gaps.

Returns the json-decoded response.

=cut

sub poll_response {
    my ($self, $method, $content, $uri, $interval, $stop_after, $good_status) = @_;

    my $now = time();
    my $result;
    my $f = repeat {
        sleep $interval;
        my $f = Future->new();
        try {
            $self->_ua->default_header("Content-Type" => "application/json");
            my $res = $self->_ua->$method($uri, Content => $content);
            #print $res->status_line, "\n";
            #print $res->content, "\n";

            if($res->code !~ /^[23]/) {
                #print "Fail ", $res->code, " ", $res->status_line, "\n";
                #print $res->content, "\n";
                # print Dumper($res);
            } else {
                $result = $res->decoded_content();
            }
            $f->done();
        } catch {
            warn "UA error: $_";
        };
        return $f;
    } until => sub { $result || time()-$now > $stop_after };

    $f->get();

    return $result;
}

sub device_code_auth {
    my ($self) = @_;

    my $ua = $self->_ua();
    my $resp = $ua->post($self->conf->{code_endpoint}, { client_id => $self->conf->{client_id} });
    if(!$resp->is_success) {
        warn "Error fetching device code endpoint: " . $resp->status_line . "\n" . $resp->content;
    }
    my $result = decode_json($resp->decoded_content());
    $self->callback_sub->("Visit: $result->{verification_url} and enter the code $result->{user_code}");
    # print Dumper($result);

    my $token_result = $self->poll_response('post',
                                            encode_json({
                                                code => $result->{device_code},
                                                client_id => $self->conf->{client_id},
                                                client_secret => $self->conf->{client_secret},
                                                        }),
                                            $self->conf->{code_token_endpoint},
                                            $result->{interval},
                                            $result->{expires_in},
        );

    
    my $token = LWP::Authen::OAuth2::AccessToken::Bearer->from_ref(decode_json($token_result));
    my $oauth2 = LWP::Authen::OAuth2->new(
        client_id => $self->conf->{client_id},
        client_secret => $self->conf->{client_secret},
        authorization_endpoint => $self->conf->{authorization_endpoint},
        token_endpoint => $self->conf->{token_endpoint},
        request_required_params => [qw/grant_type client_id client_secret code redirect_uri/],
        #scope => 'basic+ageless',
        );
    ## hmm ugly, this doesnt have a setter:
    $oauth2->{access_token} = $token;
    ## manually cos we're kinda cheating:
    $self->conf->{save_tokens}->($oauth2->token_string);
    return $oauth2;
}

1;
