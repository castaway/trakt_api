package Trakt::API;

=head1 NAME

Trakt::API - Interact with the https://trakt.tv API

=head1 SYNOPSIS

    use Trakt::API;
    my $trakt = Trakt::API->new({
      config => {
        client_secret => 'mysecet',
        client_id     => 'myid',
      },
      access_token => 'my previously stored access token',   # optional
      refresh_token => 'my previously stored refresh token', # optional
      normalise_names => sub { my ($name); do whatever; return $name; }
    });

    # Ensure logged in:
    $trakt->login();

    # Fetch my watched shows
    # /users/$username/watched/shows
    my $shows = $trakt->watched_shows($username);

    # Fetch my watched movies
    # /users/$username/watched/movies
    my $movies = $trakt->watched_movies($username);

    # Fetch my show watchlist
    # /users/$username/watchlist/shows
    my $shows = $trakt->watchlist_shows($username);

    # Fetch my movie watchlist
    # /users/$username/watchlist/movies
    my $movies = $trakt->watchlist_movies($username);

    # Get info about an episode of a show
    # /shows/$slug/seasons/$season/episodes/$episode
    my $ep_info = $trakt->show_episode($show_slug, $season_num, $episode_num);

    # Update info about watched shows
    # /sync/history
    $trakt->sync_history($show_history);

=head1 DESCRIPTION

Trakt::API is a module to allow you to interact with the
L<https://trakt.tv> API, which is documented at
L<https://trakt.docs.apiary.io>.

This module is a Work In Progress, starting with the functionality I
needed initially. Patches welcome!

Each API method will call L</login> to ensure we are still logged
in.

=head1 ATTRIBUTES

=cut

use 5.20.0;
use strictures 2;

use LWP::UserAgent;
use JSON;
use Data::Dumper;
use MiddleMan::OAuthHandler;
use LWP::Authen::OAuth2;

use Moo;

our $VERSION = '0.01';

=head2 config

Trakt API developer details, to obtain yours visit
L<https://trakt.tv/oauth/applications> and create a "new
application". This takes a HashRef, containing B<client_id> and
B<client_secret>.

    config => {
       client_id => 'myclientid',
       client_secret => 'myapisecret',
    }

=cut

has 'config' => ( is => 'ro', required => 1 );

=head2 normalise_names

A coderef which takes a string of the name, and returns it with any
normalisation you need applied to it. This is applied to each show or
movie title after the data is fetched.

    normalise_names => sub { my ($name) = @_; return $name; }

=cut

has 'normalise_names' => ( is => 'rw', required => 1);

=head2 access_token

Get/Set the access token, pass a value from a saved previous use to
skip the login (check API docs for how long tokens last).

=cut

has 'access_token' => ( is => 'rw' );

=head2 refresh_token

Get/Set the refresh token, pass a value from a saved previous use to
skip the login (check API docs for how long tokens last).

=cut

has 'refresh_token' => ( is => 'rw' );
has 'oauth' => (is => 'rw' );
has '_auth_endpoint' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/oauth/authorize' });
has '_token_endpoint' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/oauth/token' });
has '_code_endpoint' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/oauth/device/code' } );
has '_code_token_endpoint' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/oauth/device/token' });
has '_headers' => ( is => 'lazy', default => sub {
    my ($self) = @_;
    return {
        'Content-Type' => 'application/json',
#        'Authorization'=> "Bearer " . $self->access_token,
        'trakt-api-version' => 2,
        'trakt-api-key' => $self->config->{client_id},
    };
});
has '_baseuri' => ( is => 'lazy', default => sub { 'https://api.trakt.tv/'; });
# has '_ua' => ( is => 'lazy', default => sub { LWP::UserAgent->new(); });

=head1 METHODS

=head2 login

Will login to Trakt using the device code method documented in
L<https://trakt.docs.apiary.io/#reference/authentication-devices/generate-new-device-codes>,
if we don't currently have an access token.

TODO: Make this use/check refresh tokens!

=cut

sub login {
    my ($self) = @_;
    # print "CONFIG ", Dumper($self->config);
    if(!%{$self->config }
       || !$self->config->{client_id}
       || !$self->config->{client_secret}) {
        warn "Missing Trakt config: client_id or client_secret\n";
        return;
    }

    my $oa = MiddleMan::OAuthHandler->new({
        conf => {
            code_endpoint          => $self->_code_endpoint,
            code_token_endpoint    => $self->_code_token_endpoint,
            save_tokens => sub {
                my ($token_str) = @_;
                $DB::single=1;
                $self->config->{token_string} = $token_str;
            },
            %{ $self->config },
        },
        callback_sub => sub {
            my ($str) = @_;
            print "$str\n";
        },
    });
    ## this might die!
    
    ## NB: if conf->{token_string} is still valid, this just sets up
    ## the object and returns it
    my $oauth = $oa->authenticate();
    $self->oauth($oauth);
}

=head2 get($path)

Generic B<get> method usable for all Trakt API GET methods (used internally).

Returns the response content, json decoded.

=cut

sub get {
    my ($self, $path) = @_;    

    $self->login();
    
    my $uri = URI->new_abs($path, $self->_baseuri);
    print("Fetch $uri with ", Dumper($self->_headers));
    my $resp = $self->oauth->get($uri, %{ $self->_headers });

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

=head2 post($path, $content)

Generic B<post> method usable for all Trakt API POST methods.

Pass $content as a Perl HashRef or ArrayRef according to the required
path arguments, this will be json encoded for you.

die()s if the POST fails.

returns true if it succeeded.

=cut

sub post {
    my ($self, $path, $content) = @_;

    $self->login();

    my $uri = URI->new_abs($path, $self->_baseuri);
    my $resp = $self->oauth->post($uri, %{ $self->_headers }, Content => encode_json($content));
    if(!$resp->is_success) {
        die "Post to $uri failed, " . $resp->status_line;
#        say $resp->status_line;
#        print $resp->content;
    }
    return 1;
}

=head2 watched_shows($username)

Returns the users watched shows. This will return shows for users with
public data, the logged in user, or users with a friend relationship
to the logged in user.

=cut

sub watched_shows {
    my ($self, $username) = @_;
    my $json = $self->get("/users/$username/watched/shows");
    my $result = {};
    foreach my $show (@$json) {
        $result->{$self->normalise_names->($show->{show}{title})} = $show;
    }

    return $result;
}

=head2 watched_movies($username)

Returns the users watched movies. This will return movies for users with
public data, the logged in user, or users with a friend relationship
to the logged in user.

=cut

sub watched_movies {
    my ($self, $username) = @_;
    my $json = $self->get("/users/$username/watched/movies");
    my $result = {};
    foreach my $movie (@$json) {
        $result->{$self->normalise_names->($movie->{movie}{title})} = $movie;
    }

    return $result;
}

=head2 watchlist_shows($username)

Returns the users to-watch shows. This will return shows for users with
public data, the logged in user, or users with a friend relationship
to the logged in user.

=cut

sub watchlist_shows {
    my ($self, $username) = @_;
    my $json = $self->get("/users/$username/watchlist/shows");
    my $result = {};
    foreach my $show (@$json) {
        $result->{$self->normalise_names->($show->{show}{title})} = $show;
    }

    return $result;
}

=head2 watchlist_movies($username)

Returns the users to-watch movies. This will return movies for users with
public data, the logged in user, or users with a friend relationship
to the logged in user.

=cut

sub watchlist_movies {
    my ($self, $username) = @_;
    my $json = $self->get("/users/$username/watchlist/movies");
    my $result = {};
    foreach my $movie (@$json) {
        $result->{$self->normalise_names->($movie->{movie}{title})} = $movie;
    }

    return $result;
}

=head2 show_episode($showslug, $season_num, $episode_num)

Data for a specific episode of a season of a show. Show slugs are
avaible from the watched / watchlist methods. Returns data including
the title and the episodes internal id.

=cut

sub show_episode {
    my ($self, $slug, $season, $episode) = @_;
    my $json = $self->get("/shows/$slug/seasons/$season/episodes/$episode");

    return $json;
}

=head2 sync_history($content)

Trakt API docs L<https://trakt.docs.apiary.io/#reference/sync/add-to-history/add-items-to-watched-history>

Adds given show/movie/episode data to the logged-in users "Watched" history.

=cut

sub sync_history {
    my ($self, $content) = @_;

    return $self->post('/sync/history', $content);
}

=head1 SOURCE AVAILABILITY

This source is in Github:

	https://github.com/castaway/trakt_api/

=head1 AUTHOR

Jess Robinson, C<< <jrobinson@cpan.org> >>

=head1 COPYRIGHT AND LICENSE

Copyright © 2019-2020, Jess Robinson, <jrobinson@cpan.org>. All rights reserved.
You may redistribute this under the terms of the Artistic License 2.0.

=cut

1;
