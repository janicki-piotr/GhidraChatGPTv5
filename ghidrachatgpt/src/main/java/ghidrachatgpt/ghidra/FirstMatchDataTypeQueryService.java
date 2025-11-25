package ghidrachatgpt.ghidra;

import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.DataTypeQueryService;
import ghidra.program.model.data.DataType;

import java.util.ArrayList;
import java.util.List;

class FirstMatchDataTypeQueryService implements DataTypeQueryService {
    private final DataTypeManagerService realService;
    private List<DataType> cachedList;

    FirstMatchDataTypeQueryService(DataTypeManagerService realService) {
        this.realService = realService;
    }

    @Override
    public List<DataType> getSortedDataTypeList() {
        if (cachedList == null) {
            cachedList = new ArrayList<>(realService.getSortedDataTypeList());
        }
        return cachedList;
    }

    @Override
    public DataType getDataType(String filterText) {
        if (filterText == null || filterText.isEmpty()) {
            return null;
        }

        List<DataType> list = getSortedDataTypeList();

        for (DataType dt : list) {
            String name = dt.getName();
            if (filterText.equals(name)) {
                return dt;
            }
        }

        for (DataType dt : list) {
            String name = dt.getName();
            if (name.startsWith(filterText)) {
                return dt;
            }
        }

        return null;
    }
}
