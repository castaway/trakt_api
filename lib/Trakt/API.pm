package Trakt::API;

use 5.20.0;
use strictures 2;

use LWP::UserAgent;
use JSON;
use Data::Dumper;
use OAuthHandler;

use Moo;

has 'config' => ( is => 'ro', required => 1 );
has 'normalise_names' => ( is => 'rw', required => 1);
has '_auth_endpoint' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/oauth/authorize' });
has '_token_endpoint' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/oauth/token' });
has '_code_endpoint' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/oauth/device/code' } );
has '_code_token_endpoint' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/oauth/device/token' });
has 'access_token' => ( is => 'rw' );
has 'refresh_token' => ( is => 'rw' );
has '_headers' => ( is => 'lazy', default => sub {
    my ($self) = @_;
    return {
        'Content-Type' => 'application/json',
        'Authorization'=> "Bearer " . $self->access_token,
        'trakt-api-version' => 2,
        'trakt-api-key' => $self->config->{client_id},
    };
});
has '_baseuri' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/'; });
has '_ua' => ( is => 'lazy', default => sub { LWP::UserAgent->new(); });

sub login {
    my ($self) = @_;
    # print "CONFIG ", Dumper($self->config);
    warn "Missing Trakt config: client_id or client_secret" if(!%{$self->config } || !$self->config->{client_id} || !$self->config->{client_secret});

    if(!$self->access_token) {
        my $oa = OAuthHandler->new({
            conf => {
                #authorization_endpoint => $self->_auth_endpoint,
                #token_endpoint         => $self->_token_endpoint,
                code_endpoint          => $self->_code_endpoint,
                code_token_endpoint    => $self->_code_token_endpoint,
                %{ $self->config },
            },
            # The ID on jess's generic oauth endpoint thingy.  Wrong
            # initially (should be trakt not amazon), not worth the
            # effort to change now
            service => 'amazon_prime',
            callback_sub => sub {
                my ($str) = @_;
                print "$str\n";
            },
        });
        my $tokens = $oa->authenticate();
        $self->access_token($tokens->{access_token});
        $self->refresh_token($tokens->{refresh_token});
    }
}

sub get {
    my ($self, $uri) = @_;    

    $self->login();
    
    $uri = URI->new_abs($uri, $self->_baseuri);
    print("Fetch $uri with ", Dumper($self->_headers));
    my $resp = $self->_ua->get($uri, %{ $self->_headers });

    if ($resp->code == 404) {
        return { };
    } elsif ($resp->code == 502) {
        ## retry:
        sleep 1;
        return $self->trakt($uri);
    } elsif (not $resp->is_success) {
        print $resp->status_line, "\n";
        print $resp->content;
        die "Failure getting a trakt api ".$uri;
    }
    return decode_json($resp->decoded_content);
}

sub post {
    my ($self, $uri, $content) = @_;

    $self->login();

    $uri = URI->new_abs($uri, $self->_baseuri);
    my $resp = $self->_ua->post($uri, %{ $self->_headers }, Content => encode_json($content));
    if(!$resp->is_success) {
        print "Post to $uri failed";
        say $resp->status_line;
        print $resp->content;
        die;        
    }
    return 1;
}

sub watched_shows {
    my ($self) = @_;
    my $json = $self->get('/users/theorbtwo/watched/shows');
    my $result = {};
    foreach my $show (@$json) {
        $result->{$self->normalise_names->($show->{show}{title})} = $show;
    }

    return $result;
}

sub watched_movies {
    my ($self) = @_;
    my $json = $self->get('/users/theorbtwo/watched/movies');
    my $result = {};
    foreach my $movie (@$json) {
        $result->{$self->normalise_names->($movie->{movie}{title})} = $movie;
    }

    return $result;
}

sub watchlist_shows {
    my ($self) = @_;
    my $json = $self->get('/users/theorbtwo/watchlist/shows');
    my $result = {};
    foreach my $show (@$json) {
        $result->{$self->normalise_names->($show->{show}{title})} = $show;
    }

    return $result;
}


sub watchlist_movies {
    my ($self) = @_;
    my $json = $self->get('/users/theorbtwo/watchlist/movies');
    my $result = {};
    foreach my $movie (@$json) {
        $result->{$self->normalise_names->($movie->{movie}{title})} = $movie;
    }

    return $result;
}

sub show_episode {
    my ($self, $slug, $season, $episode) = @_;
    my $json = $self->get("/shows/$slug/seasons/$season/episodes/$episode");

    return $json;
}

sub sync_history {
    my ($self, $content) = @_;

    return $self->post('/sync/history', $content);
}

1;
