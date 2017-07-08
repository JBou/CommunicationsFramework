package com.ikeirnez.communicationsframework.implementation.authentication.usernamePassword;

import com.ikeirnez.communicationsframework.api.packets.Packet;

/**
 * Created by JBou on 08/07/2017.
 */
public class PacketUsernamePasswordAuthenticate implements Packet {

    private static final long serialVersionUID = 6683743303951730249L;
    private final String username;
    private final String password;

    public PacketUsernamePasswordAuthenticate(String username, String password) {
        super();
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
