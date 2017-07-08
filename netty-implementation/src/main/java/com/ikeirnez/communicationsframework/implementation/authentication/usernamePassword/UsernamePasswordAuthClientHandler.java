package com.ikeirnez.communicationsframework.implementation.authentication.usernamePassword;

import com.ikeirnez.communicationsframework.api.HookType;
import com.ikeirnez.communicationsframework.api.authentication.UsernamePasswordConnectionAuthentication;
import com.ikeirnez.communicationsframework.implementation.authentication.PacketAuthenticationStatus;
import com.ikeirnez.communicationsframework.implementation.standard.connection.ConcreteClientConnection;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

/**
 * Created by JBou on 08/07/2017.
 */
public class UsernamePasswordAuthClientHandler extends ChannelInboundHandlerAdapter {

    private ConcreteClientConnection clientConnection;
    private UsernamePasswordConnectionAuthentication authentication;

    public UsernamePasswordAuthClientHandler(ConcreteClientConnection clientConnection, UsernamePasswordConnectionAuthentication authentication) {
        this.clientConnection = clientConnection;
        this.authentication = authentication;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        if (!clientConnection.authenticated.get()) {
            ctx.channel().writeAndFlush(new PacketUsernamePasswordAuthenticate(authentication.getUsername(), authentication.getPassword()));
        } else {
            ctx.fireChannelActive();
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (!clientConnection.authenticated.get()) {
            if (msg instanceof PacketAuthenticationStatus) {
                PacketAuthenticationStatus packet = (PacketAuthenticationStatus) msg;

                if (packet.isAllowed()) {
                    clientConnection.authenticated.set(true);
                    clientConnection.logger.info("Authentication successful");
                    ctx.fireChannelActive();
                } else {
                    clientConnection.logger.info("Authentication failed");
                    clientConnection.expectingDisconnect.set(true);
                    clientConnection.getConnectionManager().callHook(clientConnection, HookType.AUTHENTICATION_FAILED);
                }
            }
        } else {
            ctx.fireChannelRead(msg);
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception { // makes sure we re-authenticate when reconnecting
        clientConnection.authenticated.set(false);
        ctx.fireChannelInactive();
    }

}
