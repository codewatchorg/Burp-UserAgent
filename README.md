# Burp-UserAgent
Automatically modify the User-Agent header in all Burp requests.

Burp UserAgent
=========

Update or set the User-Agent header in all requests to a specific value.

The extension uses the Firefox UserAgentSwitcher XML file format, and the default XML file for the extension is found here: <a href="http://techpatterns.com/downloads/firefox/useragentswitcher.xml">http://techpatterns.com/downloads/firefox/useragentswitcher.xml</a>.  If you create your own XML file, it needs to be named useragents.xml and be placed in the same directory as the main Burp jar file.

There are probably limited use cases for this extension, but at times I have found the need to use a tool or browser through Burp that didn't have an option for configuring the User-Agent header.  This was an easy extension to write so I thought why not.

Usage
=====

Steps include:
<ol>
<li>Add extension to burp</li>
<li>Create a session handling rule in Burp that invokes this extension</li>
<li>Modify the scope to include applicable tools and URLs</li>
<li>Configure the User-Agent header you want to use in the "Burp UserAgent" tab</li>
<li>Test away</li>
</ol>
