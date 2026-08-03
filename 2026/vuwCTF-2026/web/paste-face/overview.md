The service is running off of three containers, `site`, `sandbox` and `db`. `site` is exposed to the internet, but `sandbox` and `db` are both on an internal network that can be used by `site` to access the abilities of each.

`sandbox` runs a simple API endpoint at `http://localhost:9998/test` that unpickles data given to it and runs some basic tests on it. It runs in a limited pickle environment to prevent the common pickle based RCE vector, but is also in its own sandbox to prevent it from messing with the site. It can make requests to the site as it's on the same internal network, but these are not special, and it can not access the internet at large.

`db` runs a mostly complete REST API on `http://localhost:9999/` for paste and user information. More details can be accessed by getting the `/` endpoint, and looking at the methods available on each endpoint. It's a bit more fully featured than what the site can handle right now, but it's being worked on!

%% TODO: (16/03/2019) flesh this out with future plans :) %%
