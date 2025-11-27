/*
 * @(#) $Id: DefaultUAMPersistenceManager.java,v 1.1.1.1 2003/10/05 18:39:26 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk.uam;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;


public class DefaultUAMPersistenceManager implements UAMPersistenceManagerIntf {

    private UserAccountManager uam;

    private final String filename;

    public DefaultUAMPersistenceManager(String filename) {
        this.filename = filename;
    }

    private void save() {
        ObjectOutputStream oos;
        try {
            oos = new ObjectOutputStream(new FileOutputStream(filename));
            oos.writeObject(uam);
            oos.flush();
            oos.close();
        } catch (IOException ioe) {
            System.err.println("writeObject failed: " + ioe);
        }
    }

    @Override
    public UserAccountManager load() throws Exception {
        ObjectInputStream ois = null;
        uam = null;
        try {
            ois = new ObjectInputStream(new FileInputStream(filename));
        } catch (FileNotFoundException fnfe) {
            uam = new UserAccountManager();
        }

        if (uam == null) {
            uam = (UserAccountManager) ois.readObject();
        }
        return uam;
    }

    @Override
    public void addUser(String loginName, String userName, String passWord) {
        save();
    }

    @Override
    public void changePassWord(String loginName, String passWord) {
        save();
    }

    @Override
    public void remUser(String loginName) {
        save();
    }

    @Override
    public void addRole(String roleName, String desc) {
        save();
    }

    @Override
    public void remRole(String roleName) {
        save();
    }

    @Override
    public void addRoleToUser(String roleName, String loginName) {
        save();
    }

    @Override
    public void remRoleFromUser(String roleName, String loginName) {
        save();
    }
}
