/*
 * @(#) $Id: JSTKResult.java,v 1.1.1.1 2003/10/05 18:39:11 pankaj_kumar Exp $
 *
 * Copyright (c) 2002-03 by Pankaj Kumar (http://www.pankaj-k.net).
 * All rights reserved.
 *
 * The license governing the use of this file can be found in the
 * root directory of the containing software.
 */

package org.jstk;

/**
 * JSTKResult.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050318 nsano initial version <br>
 */
public class JSTKResult {
    /** */
    protected Object retval;

    /** */
    protected StringBuffer desc;

    /** */
    protected boolean success;

    /** */
    public JSTKResult() {
        this(null, false, "");
    }

    /** */
    public JSTKResult(Object retval, boolean success, String desc) {
        this.retval = retval;
        this.success = success;
        this.desc = new StringBuffer();
        this.desc.append(desc);
    }

    /** */
    public Object getRetval() {
        return retval;
    }

    /** */
    public void setRetval(Object retval) {
        this.retval = retval;
    }

    /** */
    public boolean isSuccess() {
        return success;
    }

    /** */
    public void markSuccess() {
        success = true;
    }

    /** */
    public void markFailure() {
        success = false;
    }

    /** */
    public String getText() {
        return desc.toString();
    }

    /** */
    public void appendText(String txt) {
        desc.append(txt);
    }

    /** */
    public void setText(String txt) {
        desc = new StringBuffer(txt);
    }
}
