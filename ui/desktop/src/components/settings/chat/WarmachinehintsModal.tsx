import { useState, useEffect } from 'react';
import { Button } from '../../ui/button';
import { Check } from '../../icons';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../../ui/dialog';
import { errorMessage } from '../../../utils/conversionUtils';
import { defineMessages, useIntl } from '../../../i18n';

const i18n = defineMessages({
  dialogTitle: {
    id: 'warmachinehintsModal.dialogTitle',
    defaultMessage: 'Configure Project Hints (.warmachinehints)',
  },
  dialogDescription: {
    id: 'warmachinehintsModal.dialogDescription',
    defaultMessage:
      'Provide additional context about your project to improve communication with WarMachine',
  },
  helpText1: {
    id: 'warmachinehintsModal.helpText1',
    defaultMessage:
      '.warmachinehints is a text file used to provide additional context about your project and improve the communication with WarMachine.',
  },
  helpText2: {
    id: 'warmachinehintsModal.helpText2',
    defaultMessage:
      "Please make sure {bold} extension is enabled in the extensions page. This extension is required to use .warmachinehints. You'll need to restart your session for .warmachinehints updates to take effect.",
  },
  helpText3: {
    id: 'warmachinehintsModal.helpText3',
    defaultMessage: 'See {link} for more information.',
  },
  helpTextLink: {
    id: 'warmachinehintsModal.helpTextLink',
    defaultMessage: 'using .warmachinehints',
  },
  errorReading: {
    id: 'warmachinehintsModal.errorReading',
    defaultMessage: 'Error reading .warmachinehints file: {error}',
  },
  fileFound: {
    id: 'warmachinehintsModal.fileFound',
    defaultMessage: '.warmachinehints file found at: {filePath}',
  },
  fileCreating: {
    id: 'warmachinehintsModal.fileCreating',
    defaultMessage: 'Creating new .warmachinehints file at: {filePath}',
  },
  placeholder: {
    id: 'warmachinehintsModal.placeholder',
    defaultMessage: 'Enter project hints here...',
  },
  savedSuccessfully: {
    id: 'warmachinehintsModal.savedSuccessfully',
    defaultMessage: 'Saved successfully',
  },
  close: {
    id: 'warmachinehintsModal.close',
    defaultMessage: 'Close',
  },
  saving: {
    id: 'warmachinehintsModal.saving',
    defaultMessage: 'Saving...',
  },
  save: {
    id: 'warmachinehintsModal.save',
    defaultMessage: 'Save',
  },
  failedToAccess: {
    id: 'warmachinehintsModal.failedToAccess',
    defaultMessage: 'Failed to access .warmachinehints file',
  },
  failedToSave: {
    id: 'warmachinehintsModal.failedToSave',
    defaultMessage: 'Failed to save .warmachinehints file',
  },
  developer: {
    id: 'warmachinehintsModal.developer',
    defaultMessage: 'Developer',
  },
});

const HelpText = () => {
  const intl = useIntl();

  return (
    <div className="text-sm flex-col space-y-4 text-text-secondary">
      <p>{intl.formatMessage(i18n.helpText1)}</p>
      <p>
        {intl.formatMessage(i18n.helpText2, {
          bold: <span className="font-bold">{intl.formatMessage(i18n.developer)}</span>,
        })}
      </p>
      <p>
        {intl.formatMessage(i18n.helpText3, {
          link: (
            <Button
              variant="link"
              className="text-blue-500 hover:text-blue-600 p-0 h-auto"
              onClick={() =>
                window.open(
                  'https://goose-docs.ai/docs/guides/using-warmachinehints/',
                  '_blank'
                )
              }
            >
              {intl.formatMessage(i18n.helpTextLink)}
            </Button>
          ),
        })}
      </p>
    </div>
  );
};

const ErrorDisplay = ({ error }: { error: Error }) => {
  const intl = useIntl();

  return (
    <div className="text-sm text-text-secondary">
      <div className="text-red-600">
        {intl.formatMessage(i18n.errorReading, { error: errorMessage(error) })}
      </div>
    </div>
  );
};

const FileInfo = ({ filePath, found }: { filePath: string; found: boolean }) => {
  const intl = useIntl();

  return (
    <div className="text-sm font-medium mb-2">
      {found ? (
        <div className="text-green-600">
          <Check className="w-4 h-4 inline-block" />{' '}
          {intl.formatMessage(i18n.fileFound, { filePath })}
        </div>
      ) : (
        <div>{intl.formatMessage(i18n.fileCreating, { filePath })}</div>
      )}
    </div>
  );
};

interface WarmachinehintsModalProps {
  directory: string;
  setIsWarmachinehintsModalOpen: (isOpen: boolean) => void;
}

export const WarmachinehintsModal = ({ directory, setIsWarmachinehintsModalOpen }: WarmachinehintsModalProps) => {
  const intl = useIntl();
  const warmachinehintsFilePath = `${directory}/.warmachinehints`;
  const [warmachinehintsFile, setWarmachinehintsFile] = useState<string>('');
  const [warmachinehintsFileFound, setWarmachinehintsFileFound] = useState<boolean>(false);
  const [warmachinehintsFileReadError, setWarmachinehintsFileReadError] = useState<string>('');
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    const fetchWarmachinehintsFile = async () => {
      try {
        const { file, error, found } = await window.electron.readWarmachinehints();
        setWarmachinehintsFile(file);
        setWarmachinehintsFileFound(found);
        setWarmachinehintsFileReadError(error ?? '');
      } catch (error) {
        console.error('Error fetching .warmachinehints file:', error);
        setWarmachinehintsFileReadError(intl.formatMessage(i18n.failedToAccess));
      }
    };
    if (directory) fetchWarmachinehintsFile();
  }, [directory, intl]);

  const writeFile = async () => {
    setIsSaving(true);
    setSaveSuccess(false);
    try {
      const saved = await window.electron.writeWarmachinehints(warmachinehintsFile);
      if (!saved) {
        throw new Error('Unable to save .warmachinehints');
      }
      setSaveSuccess(true);
      setWarmachinehintsFileFound(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (error) {
      console.error('Error writing .warmachinehints file:', error);
      setWarmachinehintsFileReadError(intl.formatMessage(i18n.failedToSave));
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <Dialog open={true} onOpenChange={(open) => setIsWarmachinehintsModalOpen(open)}>
      <DialogContent className="w-[80vw] max-w-[80vw] sm:max-w-[80vw] max-h-[90vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>{intl.formatMessage(i18n.dialogTitle)}</DialogTitle>
          <DialogDescription>{intl.formatMessage(i18n.dialogDescription)}</DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 pt-2 pb-4">
          <HelpText />

          <div>
            {warmachinehintsFileReadError ? (
              <ErrorDisplay error={new Error(warmachinehintsFileReadError)} />
            ) : (
              <div className="space-y-2">
                <FileInfo filePath={warmachinehintsFilePath} found={warmachinehintsFileFound} />
                <textarea
                  value={warmachinehintsFile}
                  className="w-full h-80 border rounded-md p-2 text-sm resize-none bg-background-primary text-text-primary border-border-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
                  onChange={(event) => setWarmachinehintsFile(event.target.value)}
                  placeholder={intl.formatMessage(i18n.placeholder)}
                />
              </div>
            )}
          </div>
        </div>

        <DialogFooter>
          {saveSuccess && (
            <span className="text-green-600 text-sm flex items-center gap-1 mr-auto">
              <Check className="w-4 h-4" />
              {intl.formatMessage(i18n.savedSuccessfully)}
            </span>
          )}
          <Button variant="outline" onClick={() => setIsWarmachinehintsModalOpen(false)}>
            {intl.formatMessage(i18n.close)}
          </Button>
          <Button onClick={writeFile} disabled={isSaving}>
            {isSaving ? intl.formatMessage(i18n.saving) : intl.formatMessage(i18n.save)}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
