/*
 * http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/DDJ/1999/9903/9903c/9903c.htm
 */

package vavi.crypto.enigma;

public interface EnigmaParams {

    int[] getNotchPositions();

    int[] getStartPositions();

    int getRotorCount();
}
