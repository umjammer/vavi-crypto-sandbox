/*
 * @(#) $Id: JSTKCommandAdapter.java,v 1.1.1.1 2003/10/05 18:39:10 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk;

public abstract class JSTKCommandAdapter implements JSTKCommand {

    protected static final String briefDesc = "Unspecified";

    protected static final String optionsDesc = "Unspecified";

    protected final String[] sampleUses = {
            "Unspecified"
    };

    protected final String[] useForms = {
            "Unspecified"
    };

    protected JSTKResult result;

    protected JSTKPerfData perfData = new JSTKPerfData();

    protected static final String resultDesc = "Failed";

    protected static final boolean success = false;

    @Override
    public Object execute(JSTKArgs args) throws JSTKException {
        return null;
    }

    @Override
    public String briefDescription() {
        return briefDesc;
    }

    @Override
    public String optionsDescription() {
        return optionsDesc;
    }

    @Override
    public String[] sampleUses() {
        return sampleUses;
    }

    @Override
    public String[] useForms() {
        return useForms;
    }

    @Override
    public String getResultDescription() {
        return resultDesc;
    }

    @Override
    public boolean succeeded() {
        return success;
    }

    @Override
    public boolean failed() {
        return !success;
    }

    @Override
    public void setPerfData(JSTKPerfData pData) {
        perfData = pData;
    }

    @Override
    public JSTKPerfData getPerfData() {
        return perfData;
    }
}
