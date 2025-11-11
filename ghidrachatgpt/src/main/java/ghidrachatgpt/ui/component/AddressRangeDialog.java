package ghidrachatgpt.ui.component;

import docking.DialogComponentProvider;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidrachatgpt.log.Logger;

import javax.swing.*;
import java.awt.*;
import java.util.function.BiConsumer;

public class AddressRangeDialog extends DialogComponentProvider {
    private static final Logger LOGGER = new Logger(AddressRangeDialog.class);

    private final Program program;
    private final JTextField startField = new JTextField(20);
    private final JTextField endField = new JTextField(20);
    private final BiConsumer<Address, Address> onOk;

    public AddressRangeDialog(Program program,
                              String title,
                              String startPrefill,
                              String endPrefill,
                              BiConsumer<Address, Address> onOk) {
        super(title, true /* modal */);
        this.program = program;
        this.onOk = onOk;

        if (startPrefill != null) startField.setText(startPrefill);
        if (endPrefill != null) endField.setText(endPrefill);

        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.LINE_END;
        p.add(new JLabel("Address start:"), c);
        c.gridy = 1;
        p.add(new JLabel("Address end:"), c);

        c.gridx = 1;
        c.gridy = 0;
        c.anchor = GridBagConstraints.LINE_START;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        p.add(startField, c);
        c.gridy = 1;
        p.add(endField, c);

        addWorkPanel(p);
        addOKButton();
        addCancelButton();
        setRememberSize(false);
    }

    @Override
    protected void okCallback() {
        try {
            Address start = parseToSpace(startField.getText().trim(),
                    program.getAddressFactory(),
                    // default space = entry space of program's image base
                    program.getAddressFactory().getDefaultAddressSpace());

            Address end = parseToSpace(endField.getText().trim(),
                    program.getAddressFactory(),
                    program.getAddressFactory().getDefaultAddressSpace());

            if (start == null || end == null) {
                setStatusText("Invalid address. Use forms like 08001234, 0x08001234, or space-qualified (e.g., RAM:0x20000000).");
                return;
            }
            if (start.getAddressSpace() != end.getAddressSpace()) {
                setStatusText("Start and end must be in the same address space.");
                return;
            }
            // Normalize order
            if (start.compareTo(end) > 0) {
                Address t = start;
                start = end;
                end = t;
            }

            close();
            onOk.accept(start, end);
        } catch (Exception ex) {
            setStatusText("Error: " + ex.getMessage());
        }
    }

    private static Address parseToSpace(String text, AddressFactory af, AddressSpace targetSpace) {
        if (text == null) {
            return null;
        }

        Address address = af.getAddress(text);
        if (address != null) {
            return address;
        }

        String formattedAddressString = text.trim().toLowerCase();
        if (formattedAddressString.startsWith("0x")) formattedAddressString = formattedAddressString.substring(2);
        try {
            long off = Long.parseUnsignedLong(formattedAddressString, 16);
            return targetSpace.getAddress(off);
        } catch (NumberFormatException exception) {
            LOGGER.error("Cannot parse address: " + text, exception);
            return null;
        }
    }
}
