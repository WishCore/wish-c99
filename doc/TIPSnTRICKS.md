# Using wish-cli with mist_c99

BREAKING NEWS: the cli is now available in its own package, wish-cli.
This text assumes you use the cli bundled with the nodejs wish-core

Start mist_c99 so that you listen to app server socket:

<pre>
./mist_c99 -a 9091
</pre>

Move to the directory where you have checked out wish-core#c99-app-compat

Start bin/cli like this:
<pre>
TCP=1 PORT=9091 node bin/cli
</pre>

You will be connected to the C99 wish core. Then you can send commands

<pre>
wish> identity.list()
wish> identity.get(result[0].uid);
</pre>

You can import an identity from Nodejs wish-core like this:

Start bin/cli so that it contacts your nodejs wish-core (PORT defaults to 9090)

<pre>

</pre>

<pre>
wish> identity.list()
</pre>

To export the third identity:
<pre>
wish> identity.export(result[2].uid)
wish> result.toString('hex')
</pre>
The latter step is need so that you would be able to copy-paste the data into the other wish-cli running against the C99 wish core. To import the data into C99 wish core, do this:
<pre>
wish> identity.list()
wish> identity.get(result[0].uid)
wish> identity.import(new Buffer('cut-paste-here', 'hex'), result.uid)
</pre>


