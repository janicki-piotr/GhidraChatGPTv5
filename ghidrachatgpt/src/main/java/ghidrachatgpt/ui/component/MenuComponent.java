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

import java.util.Arrays;
import javax.swing.JComponent;

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
        new IdentifyFunctionAction("GCGIdentifyFunction", getName()).setUp();

        new FindVulnerabilitiesAction("GCGFindVulnerabilities", getName()).setUp();

        new BeautifyFunctionAction("GCGBeautifyFunction", getName()).setUp();

        new DebugTestFunctionAction("GCGDebugTestFunction", getName()).setUp();

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
    }

    @Override
    public JComponent getComponent() {
        return null;
    }
}
