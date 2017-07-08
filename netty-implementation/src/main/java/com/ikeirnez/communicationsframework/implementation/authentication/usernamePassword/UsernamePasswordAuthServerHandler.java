package com.ikeirnez.communicationsframework.implementation.authentication.usernamePassword;

import com.ikeirnez.communicationsframework.api.HookType;
import com.ikeirnez.communicationsframework.api.authentication.UsernamePasswordConnectionAuthentication;
import com.ikeirnez.communicationsframework.implementation.authentication.PacketAuthenticationStatus;
import com.ikeirnez.communicationsframework.implementation.standard.connection.ConcreteServerConnection;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

/**
 * Created by JBou on 08/07/2017.
 */
public class UsernamePasswordAuthServerHandler extends ChannelInboundHandlerAdapter {

    private ConcreteServerConnection connection;
    private UsernamePasswordConnectionAuthentication authentication;

    public UsernamePasswordAuthServerHandler(ConcreteServerConnection connection, UsernamePasswordConnectionAuthentication authentication) {
        this.connection = connection;
        this.authentication = authentication;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        if (connection.authenticated.get()) {
            ctx.fireChannelActive();
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (!connection.authenticated.get()) {
            if (msg instanceof PacketUsernamePasswordAuthenticate) {
                PacketUsernamePasswordAuthenticate packet = (PacketUsernamePasswordAuthenticate) msg;
                connection.authenticated.set(authentication.getUsers().containsKey(packet.getUsername()) && authentication.getUsers().get(packet.getPassword()).equals(packet.getPassword()));
                ctx.writeAndFlush(new PacketAuthenticationStatus(connection.authenticated.get()));

                if (connection.authenticated.get()) {
                    ctx.fireChannelActive();
                } else {
                    connection.closing.set(true);
                    ctx.channel().disconnect();
                    connection.getConnectionManager().callHook(connection, HookType.AUTHENTICATION_FAILED);
                }
            }
        } else {
            ctx.fireChannelRead(msg);
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception { // makes sure we re-authenticate when reconnecting
        connection.authenticated.set(false);
        ctx.fireChannelInactive();
    }

}
