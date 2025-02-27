/*
 * @(#) $Id: JSTKCommand.java,v 1.1.1.1 2003/10/05 18:39:10 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk;

public interface JSTKCommand {
    Object execute(JSTKArgs args) throws JSTKException;

    String briefDescription();

    String optionsDescription();

    String[] sampleUses();

    String[] useForms();

    String getResultDescription();

    boolean succeeded();

    boolean failed();

    void setPerfData(JSTKPerfData pData);

    JSTKPerfData getPerfData();
}
