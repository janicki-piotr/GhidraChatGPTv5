/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ghidrachatgpt.ui.component;

import docking.ComponentProvider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.JComponent;

import docking.action.DockingAction;
import ghidra.framework.plugintool.Plugin;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.openai.GPTModel;
import ghidrachatgpt.log.LogType;
import ghidrachatgpt.ui.action.*;

public class MenuComponent extends ComponentProvider {

    public MenuComponent(Plugin plugin, String owner) {
        super(plugin.getTool(), owner, owner);
        ComponentContainer.initDockingTool(dockingTool);
        createActions();
    }

    private void createActions() {
        List<DockingAction> processingFunctions = new ArrayList<>();

        var identifyFunctionAction = new IdentifyFunctionAction("GCGIdentifyFunction", getName());
        processingFunctions.add(identifyFunctionAction);
        identifyFunctionAction.setUp();

        var findVulnerabilitiesAction = new FindVulnerabilitiesAction("GCGFindVulnerabilities", getName());
        processingFunctions.add(findVulnerabilitiesAction);
        findVulnerabilitiesAction.setUp();

        var beautifyFunctionAction = new BeautifyFunctionAction("GCGBeautifyFunction", getName());
        processingFunctions.add(beautifyFunctionAction);
        beautifyFunctionAction.setUp();

        var debugTestFunctionAction = new DebugTestFunctionAction("GCGDebugTestFunction", getName());
        processingFunctions.add(debugTestFunctionAction);
        debugTestFunctionAction.setUp();

        new UpdateTokenAction("GCGUpdateOpenAIToken", getName()).setUp();

        new UpdateInstructionsAction("GCGUpdateInstructions", getName()).setUp();

        Arrays.stream(LogType.values())
                .map(LogType::label)
                .forEach(logLevel -> new SetLogLevelAction("GCGLogLevel" + logLevel, getName(), logLevel)
                        .setUp()
                );

        Arrays.stream(GPTModel.values())
                .map(GPTModel::getName)
                .forEach(model -> new SetModelAction("GCGModel" + model, getName(), model)
                        .setUp()
                );

        new CCodeAction("GCGAttachCCode", getName()).setUp();

        new AsmCodeAction("GCGAttachAsmCode", getName()).setUp();

        new UpdateTimeoutAction("GCGUpdateTimeoutAction", getName()).setUp();

        new AutoModeToggleSkipProcessedAction("GCGAutoModeToggleSkipProcessedAction", getName()).setUp();

        new UpdateLimitFunctionsAction("GCGUpdateLimitFunctionsAction", getName()).setUp();

        new EnableAutoBeatifyAction("GCGEnableAutoBeatifyAction", getName()).setUp();

        new EnableAutoIdentifyAction("GCGEnableAutoIdentifyAction", getName()).setUp();

        new EnableAutoVulnerabilitiesAction("GCGEnableAutoVulnerabilitiesAction", getName()).setUp();

        new AutoModeEnableThunksAction("GCGAutoModeEnableThunksAction", getName()).setUp();

        new AutoModeEnableExternalsAction("GCGAutoModeEnableExternalsAction", getName()).setUp();

        var autoAllFunctionsAction = new AutoAllFunctionsAction("GCGAutoAllFunctionsAction", getName());
        processingFunctions.add(autoAllFunctionsAction);
        autoAllFunctionsAction.setUp();

        var autoAddressesFunctionsAction = new AutoAddressesFunctionsAction("GCGAutoAddressesFunctionsAction", getName());
        processingFunctions.add(autoAddressesFunctionsAction);
        autoAddressesFunctionsAction.setUp();

        var gentlyStopAutoModeAction = new GentlyStopAutoModeAction("GCGGentlyStopAutoModeAction", getName());
        gentlyStopAutoModeAction.setUp();

        ComponentContainer.initComponentStateService(new ComponentStateService(processingFunctions, gentlyStopAutoModeAction));
    }

    @Override
    public JComponent getComponent() {
        return null;
    }
}
