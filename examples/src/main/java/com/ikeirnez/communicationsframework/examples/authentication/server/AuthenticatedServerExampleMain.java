package com.ikeirnez.communicationsframework.examples.authentication.server;

import com.ikeirnez.communicationsframework.api.Callback;
import com.ikeirnez.communicationsframework.api.HookType;
import com.ikeirnez.communicationsframework.api.connection.AuthenticatedServerConnection;
import com.ikeirnez.communicationsframework.api.connection.Connection;
import com.ikeirnez.communicationsframework.api.connection.ConnectionManager;
import com.ikeirnez.communicationsframework.api.connection.ConnectionManagerFactory;
import com.ikeirnez.communicationsframework.examples.authentication.Common;

/**
 * A dummy server to demonstrate authentication usage
 * Created by iKeirNez on 27/04/2014.
 */
public class AuthenticatedServerExampleMain {

    public ConnectionManager connectionManager = ConnectionManagerFactory.getNewConnectionManager(getClass().getClassLoader()); // create a ConnectionManager to manage our connections
    public AuthenticatedServerConnection connection;
    public AuthenticatedServerExampleMain(String host, int port, char[] key) {
        // its a good idea to register hooks and listeners before attempting the connection
        // this is due to read and writes being handled asynchronously and therefore we might
        // not register everything in time

        connectionManager.addHook(HookType.CONNECTED, new Callback<Connection>() { // add hook for when we are connected
            @Override
            public void call(Connection c) {
                System.out.println("Woo! looks like we're authenticated & connected");
            }
        });

        connectionManager.addHook(HookType.AUTHENTICATION_FAILED, new Callback<Connection>() { // add hook for if authentication fails
            @Override
            public void call(Connection c) {
                System.out.println("Hmm, something went wrong, probably mismatching keys");
            }
        });

        connectionManager.registerListener(new AuthenticatedServerExampleListener()); // register listener for incoming test packet

        connection = connectionManager.newAuthenticatedServerConnection(host, port, key); // create the connection instance and populate it with our data
        connection.bind(); // begin listening for incoming connections
    }

    public static void main(String[] args) {
        new AuthenticatedServerExampleMain("localhost", 25566, Common.KEY); // Common.KEY would be replaced with your actual saved key in char[] form, probably loaded from file
    }

}