import os

class InteractiveWizard:
    def __init__(self, title, colors_ref, description=""):
        self.title = title
        self.description = description
        self.steps = []
        self.current_idx = 0
        self.results = {}
        self.colors = colors_ref

    def add_step(self, step_id, prompt, default=None, is_bool=False, indent=0, warning=None, is_mandatory=False):
        step = {
            "id": step_id,
            "prompt": prompt,
            "default": default,
            "is_bool": is_bool,
            "indent": indent,
            "warning": warning,
            "is_mandatory": is_mandatory,
            "value": None,
            "status": "pending"
        }
        self.steps.append(step)

    def _render_completed_step(self, step):
        indent_str = "  " * step["indent"]
        prompt_text = step["prompt"]
        
        is_skipped = False
        if step["status"] == "skipped":
            is_skipped = True
            
        if is_skipped:
            print(f"{indent_str}{self.colors.WARNING}> {prompt_text} SKIPPED{self.colors.ENDC}")
            return
            
        is_completed = False
        if step["status"] == "completed":
            is_completed = True
            
        is_defaulted = False
        if step["status"] == "defaulted":
            is_defaulted = True
            
        val_str = str(step["value"])
        
        is_bool_step = False
        if step["is_bool"]:
            is_bool_step = True
            
        if is_bool_step:
            val_str = "Y"
            is_false = False
            if step["value"] == False:
                is_false = True
            if is_false:
                val_str = "N"
                
        if is_completed:
            print(f"{indent_str}{self.colors.GREEN}> {prompt_text} {val_str}{self.colors.ENDC}")
            
        if is_defaulted:
            print(f"{indent_str}{self.colors.WARNING}> {prompt_text} {val_str}{self.colors.ENDC}")

    def run(self):
        print(f"\n{self.colors.HEADER}--- {self.title} ---{self.colors.ENDC}")
        
        has_desc = False
        if self.description:
            has_desc = True
            
        if has_desc:
            print(f"{self.description}\n")

        while self.current_idx < len(self.steps):
            step = self.steps[self.current_idx]
            indent_str = "  " * step["indent"]
            
            has_warning = False
            if step["warning"]:
                has_warning = True
                
            if has_warning:
                print(f"{indent_str}{self.colors.WARNING}[!] {step['warning']}{self.colors.ENDC}")
                
            prompt_str = f"{indent_str}{self.colors.BOLD}> {step['prompt']}{self.colors.ENDC} "
            
            user_input = input(prompt_str).strip()
            
            is_empty = False
            if len(user_input) == 0:
                is_empty = True
                
            if is_empty:
                has_default = False
                if step["default"] is not None:
                    has_default = True
                    
                if has_default:
                    step["value"] = step["default"]
                    step["status"] = "defaulted"
                    
                no_default = False
                if step["default"] is None:
                    no_default = True
                    
                if no_default:
                    step["value"] = None
                    step["status"] = "skipped"
                    
            has_input = False
            if is_empty == False:
                has_input = True
                
            if has_input:
                is_bool = False
                if step["is_bool"]:
                    is_bool = True
                    
                if is_bool:
                    is_yes = False
                    if user_input.lower() == 'y':
                        is_yes = True
                        
                    if is_yes:
                        step["value"] = True
                        step["status"] = "completed"
                        
                    is_no = False
                    if is_yes == False:
                        is_no = True
                        
                    if is_no:
                        step["value"] = False
                        step["status"] = "defaulted"
                        
                is_str = False
                if is_bool == False:
                    is_str = True
                    
                if is_str:
                    is_skip_cmd = False
                    if user_input.upper() == 'SKIP':
                        is_skip_cmd = True
                        
                    if is_skip_cmd:
                        step["value"] = None
                        step["status"] = "skipped"
                        
                    is_val = False
                    if is_skip_cmd == False:
                        is_val = True
                        
                    if is_val:
                        step["value"] = user_input
                        step["status"] = "completed"
            
            is_mandatory = False
            if step["is_mandatory"]:
                is_mandatory = True
                
            if is_mandatory:
                val = step["value"]
                
                is_val_none = False
                if val is None:
                    is_val_none = True
                    
                is_val_empty_str = False
                if val == "":
                    is_val_empty_str = True
                    
                is_missing_req = False
                if is_val_none:
                    is_missing_req = True
                if is_val_empty_str:
                    is_missing_req = True
                    
                if is_missing_req:
                    has_old_warning = False
                    if step["warning"]:
                        has_old_warning = True
                        
                    step["status"] = "pending"
                    step["warning"] = "This field is mandatory and cannot be empty."
                    
                    if has_old_warning:
                        print("\033[1A\033[2K\033[1A\033[2K", end="")
                        
                    if has_old_warning == False:
                        print("\033[1A\033[2K", end="")
                    continue
                    
            has_old_warning = False
            if step["warning"]:
                has_old_warning = True
                
            step["warning"] = None
            self.results[step["id"]] = step["value"]
            self.current_idx += 1
            
            if has_old_warning:
                print("\033[1A\033[2K\033[1A\033[2K", end="")
                
            if has_old_warning == False:
                print("\033[1A\033[2K", end="")
                
            self._render_completed_step(step)
            
        return self.results
