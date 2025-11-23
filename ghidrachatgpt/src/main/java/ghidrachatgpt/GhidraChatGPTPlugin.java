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

package ghidrachatgpt;


import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;
import ghidrachatgpt.ui.component.MenuComponent;

import static ghidrachatgpt.ui.action.UpdateTokenAction.censorToken;


@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = CorePluginPackage.NAME,
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "ChatGPT Plugin for Ghidra",
        description = "Brings the power of ChatGPT to Ghidra!",
        servicesRequired = {ConsoleService.class, CodeViewerService.class}
)
public class GhidraChatGPTPlugin extends ProgramPlugin {
    private static final Logger LOGGER = new Logger(GhidraChatGPTPlugin.class);

    public GhidraChatGPTPlugin(PluginTool tool) {
        super(tool);
        ComponentContainer.initGhidraChatGPTPlugin(this);
        MenuComponent menuComponent = new MenuComponent(this, getName());
        String topicName = this.getClass().getPackage().getName();
        String anchorName = "HelpAnchor";
        menuComponent.setHelpLocation(new HelpLocation(topicName, anchorName));
    }

    @Override
    public void init() {
        super.init();
        GlobalSettings.loadFromDisk();
        ComponentContainer.initConsoleService(tool.getService(ConsoleService.class));
        ComponentContainer.initCodeViewerService(tool.getService(CodeViewerService.class));
        ComponentContainer.initCPluginTool(tool);

        GlobalSettings.setAccessToken(System.getenv("OPENAI_TOKEN"));
        if (GlobalSettings.getAccessToken() != null && !GlobalSettings.getAccessToken().isEmpty()) {
            LOGGER.ok(String.format("Loaded OpenAI Token: %s", censorToken(GlobalSettings.getAccessToken())));
        }

        ComponentContainer.initGhidraChatGPTPlugin(this);
        LOGGER.ok(String.format("Default model is: %s", GlobalSettings.getOpenAiModel()));
    }
}
