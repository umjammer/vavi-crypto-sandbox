/*
 * https://archive.org/details/dr_dobbs_journal-1999_03/page/46/mode/2up
 */

package com.beechwood.crypto.chipher.enigma;

public interface EnigmaParams {

    int[] getNotchPositions();

    int[] getStartPositions();

    int getRotorCount();
}
